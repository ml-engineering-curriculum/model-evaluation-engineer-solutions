# exercise-04 — Multimodal VQA and Grounding Eval — Solution

## 1. Solution overview

A vision-language model has three independent capabilities and a single "VQA accuracy" number hides which one failed:

- **Visual perception.** Did the model see the right things in the image?
- **Language grounding.** Can the model point to *where* something is (bounding box, referring expression), not just name it?
- **Hallucination resistance.** Does the model admit it when the asked-about object is not in the image?

The exercise asks the learner to build a multimodal eval that reports a **three-metric headline** — one for each capability — plus a disaggregation by image category. Each metric has a specific, published scoring convention, and each has a specific adversarial failure mode the eval has to surface rather than smooth over.

The reference answer has four deliverables:

1. A **dataset layout** with three row types — open-ended VQA with multi-reference gold, referring-expression grounding with gold bounding boxes, and object-presence probes (POPE-style) with a balanced yes/no split.
2. A **scoring module** that implements the **VQAv2 soft accuracy** formula (`min(#matching_refs / 3, 1)`), **IoU ≥ 0.5** for grounding, and `accuracy / precision / recall / F1 / "yes"-rate` for the hallucination probes.
3. A **run driver** that emits a per-item verdict trace — raw model output, extracted answer / box, scoring breakdown — and a per-category disaggregation.
4. A **review checklist** that treats a high VQA mean paired with a 95% "yes"-rate on POPE as a known pathology, not a win — the model is agreeing with everything, which is the textbook object-hallucination signature.

This maps to the NIST AI RMF `MEASURE` function, which requires measurements to be "tested, documented, and tied to an identified operational context" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)) — a single VQA number collapses three operational contexts into one scalar. The adversarial lens is OWASP ML Top 10 **ML02 Data Poisoning** and **ML08 Model Skewing** — a vision eval whose test images overlap with pretraining data silently inflates every metric; a grounding dataset whose boxes are drawn by one annotator has a skew the eval cannot detect ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Craft Adversarial Data` names the targeted perturbation technique that exploits exactly those weaknesses — a small, label-preserving image perturbation that flips the model's answer surfaces as a reliability failure the eval must be able to detect ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Directory layout

```
multimodal_eval/
  README.md
  data/
    vqa/
      mini_vqa_v1.jsonl             # 40 rows; multi-reference gold
    grounding/
      mini_refcoco_v1.jsonl         # 40 rows; one gold box per item
    pope/
      mini_pope_v1.jsonl            # 60 rows; balanced yes/no
    images/                          # PNG/JPEG; names referenced by rows
    checksums.sha256
  scoring/
    vqa_soft.py                     # soft accuracy + answer normalization
    grounding_iou.py                # IoU and PR curve helpers
    pope.py                         # yes/no scoring + yes-rate
    normalize.py                    # answer normalization (contractions, numbers, articles)
  runner/
    run.py                          # emits Verdict traces + per-category summary
  reproduction/
    run_2026-11-20.yaml
  tests/
    test_vqa_soft.py
    test_grounding_iou.py
    test_pope.py
    test_normalize.py
```

### 2.2 Dataset schemas

Three row types, one JSONL file per type. Images referenced by relative path; the sha256 of the image is in `checksums.sha256` so a silent image replacement is a CI failure.

VQA (open-ended):

```json
{
  "id": "vqa-00014",
  "image": "images/coco_000000014.jpg",
  "image_sha256": "<hex>",
  "question": "What is the person on the left holding?",
  "references": [
    "umbrella", "umbrella", "umbrella", "umbrella",
    "umbrella", "an umbrella", "umbrella", "umbrella",
    "umbrella", "umbrella"
  ],
  "category": "object-attribute",
  "license": "cc-by-4.0",
  "provenance": "authored for exercise-04; not from VQAv2"
}
```

Grounding (referring expression → bounding box):

```json
{
  "id": "rec-00023",
  "image": "images/kitchen_000000023.jpg",
  "image_sha256": "<hex>",
  "width": 640,
  "height": 480,
  "referring_expression": "the blue mug behind the laptop",
  "gold_box": {"x": 310, "y": 142, "w": 96, "h": 124},
  "category": "occluded",
  "license": "cc-by-4.0",
  "provenance": "authored for exercise-04; not from RefCOCO"
}
```

POPE-style object-presence probe:

```json
{
  "id": "pope-00031",
  "image": "images/street_000000031.jpg",
  "image_sha256": "<hex>",
  "object": "fire hydrant",
  "ground_truth": "yes",         # object IS in the image
  "variant": "random",            # "random" | "popular" | "adversarial"
  "license": "cc-by-4.0",
  "provenance": "authored for exercise-04; not from POPE"
}
```

Four invariants to enforce in CI (section 3):

- **Image checksums match.** `images/*` SHAs match the per-row `image_sha256`. A silent image swap is a benchmark-contamination surface.
- **POPE split is balanced.** Equal counts of `ground_truth: yes` and `ground_truth: no`; mean "yes"-rate under a constant-"yes" model is 50%, so the real model's yes-rate is comparable to a sensible baseline.
- **Grounding boxes are inside the image.** `x >= 0`, `y >= 0`, `x + w <= width`, `y + h <= height`. A gold box that is partially outside the image is a data bug, not a model weakness.
- **`references` list has 10 entries for VQA.** The VQAv2 soft-accuracy formula is calibrated for 10 human references; truncating to 3 and keeping the `#matches / 3` cap inflates the score artificially. CI rejects a row with the wrong length.

### 2.3 Answer normalization (`scoring/normalize.py`)

Open-ended VQA requires normalization before any match: articles, punctuation, number words, contractions. The VQAv2 evaluation protocol standardizes this; the eval keeps the normalizer as a single committed file and tests it.

```python
"""VQA-style answer normalization.

Rules (adapted from the VQAv2 evaluation protocol):
  - lowercase
  - strip punctuation (keep decimal points inside numbers)
  - remove leading articles: 'a', 'an', 'the'
  - expand contractions: don't -> do not, etc.
  - map number words 0..10 to digits
  - collapse whitespace"""

from __future__ import annotations

import re
import string


_ARTICLES = {"a", "an", "the"}
_CONTRACTIONS = {
    "dont": "do not", "cant": "can not", "wont": "will not",
    "im": "i am", "its": "it is", "whats": "what is",
}
_NUM_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8",
    "nine": "9", "ten": "10",
}

_PUNCT_RE = re.compile(r"[^\w\s\.]")   # keep '.' for decimals like "3.5"


def normalize(text: str) -> str:
    s = text.strip().lower()
    s = s.replace("’", "'").replace("`", "'").replace("'", "")
    s = _PUNCT_RE.sub(" ", s)
    tokens = []
    for tok in s.split():
        tok = _CONTRACTIONS.get(tok, tok)
        tok = _NUM_WORDS.get(tok, tok)
        if tok not in _ARTICLES:
            tokens.append(tok)
    s = " ".join(tokens)
    s = re.sub(r"\s+", " ", s).strip()
    return s
```

### 2.4 VQA soft accuracy (`scoring/vqa_soft.py`)

The VQAv2 metric: `min(#refs that match pred / 3, 1)` after normalization. Each prediction is scored against 10 references (the 9-vs-1 trick is baked in: the formula caps the score at 1.0 after three matches).

```python
"""VQAv2 soft accuracy: min(#matches / 3, 1), with normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from .normalize import normalize


@dataclass
class VqaVerdict:
    item_id: str
    pred_raw: str
    pred_norm: str
    matches: int
    score: float
    references_norm: list[str] = field(default_factory=list)


def score_one(item: dict, pred: str) -> VqaVerdict:
    refs = item["references"]
    if len(refs) != 10:
        raise ValueError(
            f"item {item['id']}: VQAv2 scoring requires 10 references, "
            f"got {len(refs)}"
        )
    pred_n = normalize(pred)
    refs_n = [normalize(r) for r in refs]
    matches = sum(1 for r in refs_n if r == pred_n)
    score = min(matches / 3.0, 1.0)
    return VqaVerdict(
        item_id=item["id"],
        pred_raw=pred,
        pred_norm=pred_n,
        matches=matches,
        score=score,
        references_norm=refs_n,
    )
```

Properties the implementation must satisfy (`test_vqa_soft.py`):

- A prediction matching all 10 references scores exactly `1.0`.
- A prediction matching 3 or more references scores `1.0`.
- A prediction matching 2 references scores `2/3`.
- A prediction matching 0 references scores `0.0`.
- Articles are ignored: `"the umbrella"` and `"umbrella"` score the same against references `["umbrella", ...]`.
- `"2"` and `"two"` normalize to the same token.
- A reference list of the wrong length raises; the scorer does not silently reinterpret the cap.

### 2.5 Grounding IoU (`scoring/grounding_iou.py`)

A grounding prediction is a bounding box. The score is `1` if `IoU(pred_box, gold_box) >= 0.5`, else `0`. Mean accuracy is the share of items that cleared the threshold.

```python
"""Bounding-box IoU and threshold scoring for referring expression grounding.

Convention: boxes are {x, y, w, h} in pixel coordinates; x,y is the
top-left corner."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GroundingVerdict:
    item_id: str
    pred_box: dict | None
    gold_box: dict
    iou: float
    passed: bool


IOU_THRESHOLD = 0.5


def iou(a: dict, b: dict) -> float:
    ax1, ay1 = a["x"], a["y"]
    ax2, ay2 = ax1 + a["w"], ay1 + a["h"]
    bx1, by1 = b["x"], b["y"]
    bx2, by2 = bx1 + b["w"], by1 + b["h"]

    inter_x1 = max(ax1, bx1)
    inter_y1 = max(ay1, by1)
    inter_x2 = min(ax2, bx2)
    inter_y2 = min(ay2, by2)
    inter_w = max(0, inter_x2 - inter_x1)
    inter_h = max(0, inter_y2 - inter_y1)
    inter = inter_w * inter_h

    area_a = a["w"] * a["h"]
    area_b = b["w"] * b["h"]
    union = area_a + area_b - inter
    if union <= 0:
        return 0.0
    return inter / union


def score_one(item: dict, pred_box: dict | None) -> GroundingVerdict:
    gold = item["gold_box"]
    if pred_box is None:
        return GroundingVerdict(item["id"], None, gold, 0.0, False)
    i = iou(pred_box, gold)
    return GroundingVerdict(item["id"], pred_box, gold, i, i >= IOU_THRESHOLD)
```

Tests (`test_grounding_iou.py`):

- Identical boxes: IoU = 1.
- Disjoint boxes: IoU = 0.
- A box inside another: IoU = area_inner / area_outer.
- A box with the gold flipped left-right at the same area: IoU = 0 (sanity on coordinate handling).
- A `pred_box=None` is scored as `passed=False, iou=0.0`; the scorer does not crash.
- A negative-width box (model emitted `w=-5`) does not produce a negative-area union; the code clamps to 0.

### 2.6 POPE scoring (`scoring/pope.py`)

POPE (Polling-based Object Probing Evaluation) is a yes/no probe. The signal is not just accuracy — the *yes-rate* is diagnostic. A model that answers "yes" to everything scores 50% on a balanced set and will look identical to a chance model; the yes-rate reveals the pathology.

```python
"""POPE-style scoring: accuracy, precision, recall, F1, and yes-rate.

The yes-rate is the fraction of all items (regardless of ground truth)
for which the model said 'yes'. A yes-rate far from 0.5 on a balanced
split indicates agreement bias (hallucination) or the opposite
(over-refusal)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PopeVerdict:
    item_id: str
    ground_truth: str   # "yes" | "no"
    pred: str           # "yes" | "no" | "unparseable"
    correct: bool


def parse_yes_no(text: str) -> str:
    t = text.strip().lower()
    if t.startswith("yes") or t == "y":
        return "yes"
    if t.startswith("no") or t == "n":
        return "no"
    # A model that said "there is a hydrant visible in the image" — we do
    # not try to re-interpret free text as yes/no. If the prompt was a
    # yes/no question and the model did not answer with one, it is
    # unparseable.
    return "unparseable"


def score_one(item: dict, pred_text: str) -> PopeVerdict:
    pred = parse_yes_no(pred_text)
    gt = item["ground_truth"]
    return PopeVerdict(
        item_id=item["id"],
        ground_truth=gt,
        pred=pred,
        correct=(pred == gt),
    )


def summary(verdicts: list[PopeVerdict]) -> dict:
    n = len(verdicts)
    tp = sum(1 for v in verdicts if v.ground_truth == "yes" and v.pred == "yes")
    tn = sum(1 for v in verdicts if v.ground_truth == "no"  and v.pred == "no")
    fp = sum(1 for v in verdicts if v.ground_truth == "no"  and v.pred == "yes")
    fn = sum(1 for v in verdicts if v.ground_truth == "yes" and v.pred == "no")
    unp = sum(1 for v in verdicts if v.pred == "unparseable")
    pred_yes = sum(1 for v in verdicts if v.pred == "yes")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )
    return {
        "n": n,
        "accuracy":  (tp + tn) / n if n else 0.0,
        "precision": precision,
        "recall":    recall,
        "f1":        f1,
        "yes_rate":  pred_yes / n if n else 0.0,
        "unparseable_fraction": unp / n if n else 0.0,
    }
```

Rules:

- **"Unparseable" is first-class.** A model that answers "the hydrant is visible" to a yes/no question is not "yes" and not "no"; it did not follow the prompt. Bucket it; do not coerce.
- **Report yes-rate.** On a balanced split, `yes_rate ≈ 0.5` is the sign that the model is actually making decisions; `yes_rate >= 0.8` with high accuracy means the test set is imbalanced or the model is biased; `yes_rate >= 0.9` on a balanced set means the eval is measuring agreement, not perception.

### 2.7 Runner and verdict trace

The runner produces one `Verdict` per item across all three row types and a combined report. Verdicts are serialized as JSONL so a reviewer three months later can replay the scoring without rerunning the model.

```python
# runner/run.py (sketch)
from collections import defaultdict
from scoring.vqa_soft    import score_one as score_vqa
from scoring.grounding_iou import score_one as score_grounding
from scoring.pope        import score_one as score_pope, summary as pope_summary

def run(records, model_outputs):
    vqa_verdicts = []
    gr_verdicts  = []
    po_verdicts  = []
    for r in records:
        pred = model_outputs[r["id"]]
        if r.get("references") is not None:
            vqa_verdicts.append(score_vqa(r, pred))
        elif r.get("gold_box") is not None:
            gr_verdicts.append(score_grounding(r, pred.get("box")))
        elif r.get("ground_truth") in ("yes", "no"):
            po_verdicts.append(score_pope(r, pred))

    by_cat = defaultdict(list)
    for v in vqa_verdicts:
        cat = _cat_of(records, v.item_id)
        by_cat[cat].append(v.score)
    vqa_cat_means = {c: sum(xs) / len(xs) for c, xs in by_cat.items()}

    return {
        "vqa": {
            "n": len(vqa_verdicts),
            "mean_soft_acc": sum(v.score for v in vqa_verdicts) / len(vqa_verdicts),
            "by_category": vqa_cat_means,
        },
        "grounding": {
            "n": len(gr_verdicts),
            "acc_at_iou_0_5": sum(1 for v in gr_verdicts if v.passed) / len(gr_verdicts),
            "mean_iou": sum(v.iou for v in gr_verdicts) / len(gr_verdicts),
        },
        "pope": pope_summary(po_verdicts),
    }
```

### 2.8 Reproduction manifest

```yaml
run_id: mm_mini_v1_opus-4-7_2026-11-20
datasets:
  vqa: data/vqa/mini_vqa_v1.jsonl
  grounding: data/grounding/mini_refcoco_v1.jsonl
  pope: data/pope/mini_pope_v1.jsonl
dataset_sha256:
  vqa:        <hex>
  grounding:  <hex>
  pope:       <hex>
images_sha256_file: data/checksums.sha256
model:
  id: claude-opus-4-7
  decoding:
    temperature: 0.0
    max_tokens: 128
seed: 20261120
cli: "python -m runner.run --vqa data/vqa/mini_vqa_v1.jsonl --grounding data/grounding/mini_refcoco_v1.jsonl --pope data/pope/mini_pope_v1.jsonl --model claude-opus-4-7 --seed 20261120"
results:
  vqa:
    n: 40
    mean_soft_acc: 0.68
    by_category:
      "object-attribute": 0.72
      "spatial":           0.61
      "counting":          0.44
  grounding:
    n: 40
    acc_at_iou_0_5: 0.55
    mean_iou:       0.52
  pope:
    n: 60
    accuracy:   0.78
    precision:  0.74
    recall:     0.87
    f1:         0.80
    yes_rate:   0.59
    unparseable_fraction: 0.03

verdict:
  vqa_counting: "revise"      # 0.44 is far below the model's category mean
  grounding:    "revise"      # 0.55 at IoU >= 0.5 trails the 0.65 internal target
  pope:         "proceed"     # accuracy 0.78, yes_rate 0.59 is within +/-0.1 of 0.5
```

## 3. Validation steps

1. **Image integrity.** Every `image_sha256` on a row matches the file on disk at the referenced path. CI regenerates `checksums.sha256` and diffs against the committed file.
2. **Normalizer round-trip.** `normalize(normalize(x)) == normalize(x)` for every reference string in every VQA row.
3. **VQA reference count.** CI asserts `len(references) == 10` on every VQA row. The soft-accuracy cap depends on 10 refs.
4. **IoU property tests.** `test_grounding_iou.py` pins IoU=1 for identical boxes, IoU=0 for disjoint, correct values for enclosed boxes, and no crash on `pred_box=None` or negative widths.
5. **POPE balance.** CI asserts the POPE JSONL has equal numbers of `ground_truth: yes` and `ground_truth: no`; the readout's `yes_rate` is directly comparable to 0.5.
6. **Unparseable is first-class.** A test fires `"the hydrant is visible"` at `parse_yes_no` and asserts `"unparseable"`; the summary includes `unparseable_fraction` in the output.
7. **Category disaggregation present.** The VQA summary has at least one `by_category` entry. A row without `category` raises a clear error; the eval refuses to roll everything into one bucket.
8. **Grounding boxes inside image.** CI asserts `x + w <= width` and `y + h <= height` on every gold box.
9. **Deterministic rescoring.** With model outputs cached, two consecutive runs of the scorer produce the same verdicts. A diff of `verdicts.jsonl` across reruns is empty.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a three-metric, category-disaggregated measurement**, not a single VQA number.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Separate row types for VQA, grounding, and POPE | 1 | Three JSONL files; each has its own schema check. |
| R2 | VQA soft accuracy implemented and tested (`min(matches/3, 1)`) | 2 | `vqa_soft.py`; properties pinned in `test_vqa_soft.py`. |
| R3 | Normalizer handles articles, punctuation, number words, contractions and is idempotent | 1 | `normalize.py`; `test_normalize.py`. |
| R4 | Grounding IoU implemented with pixel-coord convention and `IoU >= 0.5` threshold | 2 | `grounding_iou.py`; tests for identical / disjoint / enclosed / `None`. |
| R5 | POPE scoring reports accuracy, precision, recall, F1, yes-rate, and unparseable fraction | 2 | `pope.py.summary`; manifest reports all six. |
| R6 | VQA results are disaggregated by category | 1 | `by_category` block in the readout. |
| R7 | Image checksums are committed and enforced | 1 | `checksums.sha256`; CI diffs against disk. |

**Passing bar:** 7 / 10. R5 is non-negotiable: without the yes-rate column, a hallucinating model looks like a confident one.

Reviewer checklist:

- [ ] POPE split is balanced; `yes_rate` is reported.
- [ ] A yes-rate above 0.8 on a balanced set forces `verdict: revise` on POPE regardless of accuracy.
- [ ] VQA rows have 10 references; the scorer refuses non-10 lists.
- [ ] Grounding IoU is correct for identical boxes (= 1) and disjoint boxes (= 0).
- [ ] `pred_box=None` is handled; the scorer does not crash.
- [ ] Category disaggregation is reported; counting is called out separately where present.
- [ ] Image SHAs match disk; the checksum file is committed.
- [ ] Decoding is at `temperature=0.0`; two runs of the scorer on the same outputs produce identical verdicts.
- [ ] Verdict is per-capability (`vqa`, `grounding`, `pope`), not a single multimodal number.

## 5. Common mistakes

- **One "VQA accuracy" for everything.** Rolls perception, grounding, and hallucination resistance into a scalar. A model that shifts failure modes between minor versions looks stable; the reality is the bugs just moved.
- **Exact match on raw VQA strings.** `"the umbrella"` and `"umbrella"` disagree; `"2"` and `"two"` disagree. Use the normalizer.
- **Truncating VQA references to 3 and keeping `min(matches/3, 1)`.** The cap was calibrated for 10 references; a 3-reference list inflates scores by a factor of up to 10/3. CI enforces 10.
- **Grounding scored as "did the output mention the right object" instead of IoU.** A model that says "the blue mug is in the upper right" without a box gets credit; a model that returns the correct box gets the same. IoU separates perception-of-what from perception-of-where.
- **IoU convention bug.** `{x, y, x2, y2}` vs. `{x, y, w, h}` vs. `[x_center, y_center, w, h]` vs. normalized vs. pixel — one wrong assumption drops mean IoU by 50 points. Pick one; document it in the schema; test identical boxes = 1.
- **No "unparseable" bucket on POPE.** A model that wrote a paragraph instead of yes/no is coerced to a fixed label and the error is hidden. Bucket unparseable and report the fraction.
- **Hallucination detected by accuracy alone.** A model that answers "yes" to everything scores 50% on a balanced set — same as a chance model. Report yes-rate; gate on `|yes_rate - 0.5| <= 0.1` for a balanced split.
- **POPE split not balanced.** 70% "yes", 30% "no". The best cheap strategy is "always yes"; accuracy of 70% looks good. Keep the split 50/50 and publish both splits if comparison is needed.
- **Images unversioned.** A graphic designer re-crops `images/coco_000000014.jpg` and the eval's numbers shift silently next month. Commit SHAs; fail CI on mismatch.
- **Grounding boxes outside the image.** A human annotator drew a box with `x + w > width`. The scorer silently clips and IoU is near-zero. Validate at ingest; reject rows that violate.
- **Model asked a yes/no with chain-of-thought enabled.** The model reasons for 300 tokens and then forgets to answer. Set `max_tokens` short enough to force a direct answer on POPE; let VQA and grounding have more.
- **Mixing multi-reference and single-reference VQA items.** The soft-accuracy formula assumes 10 refs. If you have single-reference items, use strict accuracy for them and report the two numbers separately; do not pretend the same formula applies.
- **No category disaggregation.** A VQA mean of 0.68 hides counting at 0.44 and object-attribute at 0.80. The "revise" is on counting; the headline mean hides that.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires component-level measurements tied to operational context; a multimodal eval with one scalar fails that bar. The three-metric decomposition and category disaggregation are the direct operationalization.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML02 Data Poisoning** and **ML08 Model Skewing** are the risks a vision eval with unpinned images and single-annotator ground truth accepts; image SHAs plus a committed schema are the direct controls.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` names the small-perturbation technique against vision models; a multimodal eval that cannot separate perception, grounding, and hallucination resistance cannot tell which of the three a perturbation broke.

<!-- Local exercise context: the three mini datasets (`mini_vqa_v1`, `mini_refcoco_v1`, `mini_pope_v1`), the `IOU_THRESHOLD = 0.5` grounding cutoff, the POPE three-variant convention (random, popular, adversarial), and the 10-reference VQAv2 soft-accuracy cap are illustrative defaults for a general-purpose multimodal eval. Rewrite them for the image domain, grounding convention, and refusal policy of your own eval before adopting. VQAv2, RefCOCO, and POPE are named here as practitioner implementations the eval design draws from; they are not official standards in the sense the three references cited above are. Code-generation evaluation is in [exercise-01](../exercise-01-pass-at-k-with-sandbox-execution/SOLUTION.md); math eval extraction and equivalence is in [exercise-02](../exercise-02-math-eval-with-robust-extraction/SOLUTION.md); RAG eval with RAGAS and TruLens is in [exercise-03](../exercise-03-rag-eval-with-ragas-and-trulens/SOLUTION.md); the product-shaped harness bundling the four is in [exercise-05](../exercise-05-product-shaped-eval-suite-design/SOLUTION.md). -->
