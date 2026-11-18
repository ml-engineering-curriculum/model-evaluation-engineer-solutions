## exercise-03 — Judge vs Human Calibration Study — Solution

### 1. Solution overview

A judge prompt without a calibration study is a measurement instrument without a reference reading. The exercise asks the learner to run a **judge-vs-human calibration study**: pick a set of items, collect human labels under a documented protocol, run the judge on the same items, and report agreement in a way that a reviewer can act on.

The reference answer has five deliverables:

1. A **study design** — item sampling plan, number of human raters per item, adjudication rule, and the judge configuration under test.
2. A **human labelling protocol** — committed rater instructions, the exact rubric from [exercise-01](../exercise-01-absolute-and-pairwise-rubric-design/SOLUTION.md), and a calibration/training round before the real labels are collected.
3. An **agreement analysis** — inter-rater agreement (human ↔ human) *first*, then judge-vs-human agreement, with the right statistic for each mode (absolute vs pairwise).
4. A **disagreement audit** — a structured review of every item where the judge and the human majority disagreed, with each disagreement labelled as `judge_error`, `human_error`, `ambiguous_item`, or `rubric_gap`.
5. A **decision contract** — whether the judge is approved for the headline eval, approved only as a diagnostic, or rejected until the rubric / prompt / judge model is changed.

This maps directly to the NIST AI RMF `MEASURE` function, which requires both validation against an operational context and documentation of the measurement's reliability ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML08 Model Skewing** — a judge that systematically disagrees with humans on a specific slice is a measurement instrument that will concentrate false positives / negatives on that slice, and that distortion is exactly what a motivated actor can exploit ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Craft Adversarial Data` describes the attacker who writes responses optimized for the specific judge bias the study would surface ([MITRE ATLAS](https://atlas.mitre.org/)).

### 2. Worked implementation

#### 2.1 Study design

The study design is committed as YAML before any labels are collected. Changing it mid-run invalidates the agreement numbers.

```yaml
# calibration/study_v1.yaml
study_id: judge_calibration_helpfulness_v1
mode: pairwise      # must match the headline eval mode from exercise-01
rubric_id: helpfulness_v1
rubric_version: "1.0"
judge:
  model: "<org>/<model>"
  revision: "<sha>"
  decoding: {temperature: 0.0, top_p: 1.0, seed: 1234}
  prompt_version: "judge_pairwise.prompt.j2@<sha>"

sampling:
  pool_size: 500            # size of the full item pool
  study_size: 150           # items to label in this study
  stratification:
    - name: length_ratio    # ensure we see short/short, long/long, mixed
      bins: [[0, 0.5], [0.5, 1.5], [1.5, 999]]
      min_per_bin: 30
    - name: topic
      bins: ["code", "qa", "chat", "summarization"]
      min_per_bin: 25
  seed: 20261117

raters:
  per_item: 3               # 3 humans per item; majority vote with explicit tie handling
  pool: "internal_sme_v1"   # named rater pool, qualifications documented in raters.md
  blinding:
    judge_hidden_from_rater: true
    candidate_identities_hidden: true
    position_randomized_per_rater: true

adjudication:
  rule: majority_of_three   # 2 or 3 agree = majority label
  ties:
    pairwise:  "tie"        # 1-1-1 across {A, B, tie} -> adjudicate to tie
    absolute:  "median"     # 3 scores on 1-5 scale -> median

power:
  target_kappa_ci_halfwidth: 0.05
  min_n: 120
  rationale: "At n=120 with majority-of-3 the Wilson CI for kappa is ~±0.05 under expected agreement; smaller studies cannot distinguish moderate from substantial agreement."
```

Design rules worth internalizing:

- **Stratify, do not iid-sample.** A random sample underweights the edges (very short vs very long responses, rare topics) where judge bias concentrates. Stratification is cheap insurance.
- **Blind the humans.** Raters must not see which response came from which candidate, and the position must be randomized *per rater*. Otherwise the rater's position bias is confounded with the judge's.
- **Fix the judge config up front.** The judge used in the study is the judge that gets approved (or rejected). You cannot "adjust" the prompt after you see the agreement numbers without starting the study over.
- **Power the study.** 30 items is a hunch, not a study. The rule-of-thumb minimum for a usable kappa CI is ~120 items with 3 raters; `min_n` in the YAML is the pre-committed floor.

#### 2.2 Human labelling protocol

The rater instructions are the rubric from [exercise-01](../exercise-01-absolute-and-pairwise-rubric-design/SOLUTION.md) plus:

- A **worked example** for every rating level / verdict option, drawn from a held-out pilot set (not the study items).
- A **training round** of 20 items with known-correct labels. Raters who disagree with the gold label on > 20% of the training set are retrained or removed from the pool; their training labels do not count toward the study.
- A **time budget** per item (e.g., 90 seconds). Raters who go significantly over budget are flagged — long rater deliberation time often correlates with ambiguous items, which is signal for the disagreement audit.
- A **single-tab UI** — the rater sees the question, both responses (slot-randomized), the rubric, and the verdict buttons. No scratch pad, no retract button after submit; this is a simple labelling task, not an essay prompt.

A fragment of the rater instructions:

```
You will see a question followed by two responses labeled Response 1 and
Response 2. They are produced by two different assistants. You do not know
which is which. Pick the better response per the rubric below. Pick "tie"
when the responses are substantively equivalent on the rubric OR when you
cannot cite a specific rubric-anchored reason one is better.

"Tie" is not a last resort. Pick it when it is the correct answer.

If the question is unanswerable, if either response refuses, or if either
response is off-topic, use the "flag" button and select the applicable flag.
Do not try to score a flagged item on the rubric.
```

#### 2.3 Running the judge

The judge is run on the same items with the same position randomization each rater saw, but the output is kept hidden from the raters until after labelling completes. Each item is also judged *twice* with slots swapped (see [exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md)); the swap-collapsed verdict is what gets compared to the human majority.

```python
# calibration/run_judge.py (sketch)
from pairwise_controls.swap import collapse, PerOrderResult


def judge_item(item, cand_x, cand_y, judge_fn, seed):
    xy = judge_fn(item, slot_A=cand_x, slot_B=cand_y, seed=seed)
    yx = judge_fn(item, slot_A=cand_y, slot_B=cand_x, seed=seed)
    per = (
        PerOrderResult(order="xy", verdict=xy["verdict"], judge_raw=xy),
        PerOrderResult(order="yx", verdict=yx["verdict"], judge_raw=yx),
    )
    collapsed, inconsistent = collapse(per)
    return {
        "item_id": item["id"],
        "x": cand_x["id"], "y": cand_y["id"],
        "per_order": per,
        "collapsed_winner": collapsed,
        "inconsistency": inconsistent,
    }
```

#### 2.4 Agreement statistics

**First, measure human ↔ human agreement.** If humans don't agree with each other, there is no stable "truth" to validate the judge against. For pairwise verdicts with 3 raters, report both:

- **Majority rate.** Fraction of items where ≥ 2 of 3 raters picked the same verdict. This is the practical floor — items where it fails are intrinsically ambiguous.
- **Fleiss' kappa** across the 3-rater labels. Fleiss' kappa generalizes Cohen's kappa to more than two raters; it corrects for agreement expected by chance.

Interpretation band for kappa (Landis & Koch convention; commit the labels, not the folklore):

```yaml
# calibration/thresholds.yaml
kappa_bands:
  poor:        [-1.0, 0.00]
  slight:      [0.00, 0.20]
  fair:        [0.20, 0.40]
  moderate:    [0.40, 0.60]
  substantial: [0.60, 0.80]
  almost_perfect: [0.80, 1.00]
```

Minimal implementation:

```python
# calibration/agreement.py
import math
from collections import Counter


def fleiss_kappa(ratings_per_item: list[list[str]], categories: list[str]) -> float:
    """ratings_per_item[i] is a list of labels (strings) for item i.
       categories is the fixed set of label strings (e.g. ["A", "B", "tie"]).
    """
    n = len(ratings_per_item)
    N = len(categories)
    cats = {c: i for i, c in enumerate(categories)}

    # Build item x category matrix of counts
    M = [[0] * N for _ in range(n)]
    totals = []
    for i, labels in enumerate(ratings_per_item):
        c = Counter(labels)
        r = sum(c.values())
        totals.append(r)
        for cat, count in c.items():
            M[i][cats[cat]] = count

    # P_i = ( sum_j n_ij*(n_ij - 1) ) / ( n*(n-1) )
    P_i = []
    for i in range(n):
        r = totals[i]
        if r < 2:
            continue
        s = sum(M[i][j] * (M[i][j] - 1) for j in range(N))
        P_i.append(s / (r * (r - 1)))
    P_bar = sum(P_i) / len(P_i)

    # Expected agreement
    total_ratings = sum(totals)
    p_j = [sum(M[i][j] for i in range(n)) / total_ratings for j in range(N)]
    Pe = sum(pj * pj for pj in p_j)

    return (P_bar - Pe) / (1 - Pe) if Pe < 1 else float("nan")


def bootstrap_ci(ratings_per_item, categories, n_resamples=2000, seed=1234):
    import random
    rng = random.Random(seed)
    n = len(ratings_per_item)
    samples = []
    for _ in range(n_resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        boot = [ratings_per_item[i] for i in idx]
        samples.append(fleiss_kappa(boot, categories))
    samples.sort()
    return samples[int(0.025 * n_resamples)], samples[int(0.975 * n_resamples)]
```

**Then, judge ↔ human agreement.** Three different numbers, all of which go on the result card:

- **Cohen's kappa (judge vs human majority).** The judge is a single rater; the human reference is the adjudicated majority. Report the point estimate and a 95% bootstrap CI (pin the seed).
- **Raw agreement rate.** Easier for non-statisticians to read; keep it alongside kappa, not instead of it.
- **Confusion matrix.** The 3 × 3 (A / B / tie) matrix of judge vs human majority is the single most useful artifact for the disagreement audit; it tells you immediately whether the judge is biased toward a side or toward "no tie."

For an **absolute** rubric, the equivalent statistics are:

- **Intraclass Correlation Coefficient (ICC(2,1))** between judge and the per-item human median. Pearson correlation is a weaker alternative — it ignores calibration offset; report both.
- **Mean absolute error** on the 1–5 scale.
- A **calibration plot**: binned judge score on the x-axis, mean human score on the y-axis, with a diagonal reference line.

#### 2.5 Disagreement audit

Every item where the judge disagrees with the human majority is reviewed by a human adjudicator (preferably a rubric author, not a study rater). Each disagreement is labelled with one of:

```yaml
# calibration/disagreement_labels.yaml
labels:
  - judge_error:    "Judge misread the response or the rubric; humans are right."
  - human_error:    "Human majority is wrong under the rubric; judge is right."
  - ambiguous_item: "Rubric could defensibly support either verdict on this item."
  - rubric_gap:     "Neither verdict is defensible because the rubric does not cover this case."
```

Report the label distribution. The two numbers that drive the decision contract:

- **`judge_error` fraction** — the actual error rate of the judge versus a properly adjudicated human reference. A kappa of 0.7 with 80% `judge_error` disagreements is very different from a kappa of 0.7 with 10% `judge_error` and 70% `ambiguous_item`.
- **`rubric_gap` fraction** — a rubric that cannot cover 15% of items is not ready for production; fix the rubric before you re-run the study.

#### 2.6 Decision contract

The decision is committed as a short matrix, not left to a reviewer's taste:

```yaml
# calibration/decision.yaml
headline_use:
  require:
    - "fleiss_kappa_human >= 0.60"       # humans must agree with themselves
    - "cohen_kappa_judge  >= 0.60"       # judge reaches 'substantial' band
    - "judge_error_fraction <= 0.20"     # at most 20% of disagreements are judge errors
    - "rubric_gap_fraction <= 0.05"      # at most 5% of items reveal a rubric gap
    - "slot_a_rate_95ci inside [0.45, 0.55]"   # position bias control from exercise-02
diagnostic_only:
  require:
    - "fleiss_kappa_human >= 0.40"
    - "cohen_kappa_judge  >= 0.40"
rejected:
  when: "cohen_kappa_judge < 0.40 OR judge_error_fraction > 0.35"
```

- **Headline use.** The judge may be used to compute the published win-rate for this rubric and this item domain. Re-run the study when the judge model, the judge prompt, or the rubric version changes.
- **Diagnostic only.** The judge may be used for internal regression signals and dashboards, but not for externally published numbers. Humans adjudicate the published number.
- **Rejected.** The judge may not be used for this rubric. Either change the judge model, rewrite the prompt, or fix the rubric gaps and re-run.

### 3. Validation steps

1. **Pre-study pilot.** Run the full pipeline end-to-end on 20 items with 2 raters and no formal analysis. The goal is to catch tooling bugs (misaligned slot randomization, judge timing out on long responses, rater UI confusion) before you spend real rater time.
2. **Blinding audit.** Spot-check 10 random labelling tasks: can a rater tell from the UI which response is which candidate? If yes, blinding is leaking (file paths, cached headers, model-specific formatting) and the human labels are contaminated.
3. **Stratum coverage check.** Confirm `min_per_bin` is actually met for every stratification axis. Studies regularly under-cover an edge stratum and the kappa reported on the whole study masks a terrible kappa on that stratum.
4. **Re-run determinism.** Re-run the judge on the same items with the same seed. Verdicts must be identical. If not, something is nondeterministic in the judge pipeline and the kappa is noisy for a reason that has nothing to do with the judge's quality.
5. **Bootstrap CI pinning.** The bootstrap seed is in `study_v1.yaml`. Changing the seed between the point estimate and the CI is how reports quietly become irreproducible.
6. **Disagreement audit coverage.** Every disagreement must be labelled; unlabelled disagreements are not "neutral," they are missing data. The audit worksheet reports completion as a percentage; headline-use approval requires 100%.
7. **Confusion-matrix sanity.** Inspect the confusion matrix for a diagonal-heavy pattern with a visible "tie" row/column. A matrix where the judge never emits `tie` even when humans do is a prompt-level bug (the tie rule is not firing) and must be fixed before the study is re-run.

### 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Study design is committed before labels are collected | 2 | `study_v1.yaml` with sampling, raters, adjudication, power is in the repo; no mid-study edits. |
| R2 | Humans are blinded to candidate identity and position is randomized per rater | 1 | UI capture or a signed-off attestation; pilot's blinding audit is documented. |
| R3 | Inter-human agreement is reported *before* judge-vs-human | 1 | Fleiss' kappa + majority rate for humans on the result card, with CI. |
| R4 | The right agreement statistic for the mode is used | 1 | Cohen's kappa for pairwise majority; ICC + calibration plot for absolute. |
| R5 | Confusion matrix is in the report | 1 | 3×3 (A/B/tie) or 5×5 (absolute) matrix with row/column totals. |
| R6 | Disagreement audit labels every disagreement | 2 | All disagreements labelled as judge_error / human_error / ambiguous_item / rubric_gap; distribution surfaced. |
| R7 | Position / length bias audits from exercise-02 run alongside the study | 1 | Slot-A rate and beta_len reported with the kappa; thresholds enforced. |
| R8 | A commit-level decision rule assigns headline / diagnostic / rejected | 1 | `decision.yaml` thresholds are explicit; the study's output is one of the three outcomes with evidence. |

**Passing bar:** 7 / 10.

Reviewer checklist:

- [ ] `study_v1.yaml` is dated and in Git before the first label is written.
- [ ] Rater pool and qualifications are documented in `raters.md`.
- [ ] Human kappa is reported before judge kappa — if humans are below `fleiss_kappa_human >= 0.40`, no judge analysis is meaningful.
- [ ] CI half-width for the primary kappa is ≤ 0.08; otherwise `min_n` was too low.
- [ ] Every disagreement has a disagreement label; audit coverage is 100%.
- [ ] Confusion matrix is in the report; "tie" row and column are populated or the tie rule is fixed.
- [ ] Decision outcome is stated verbatim ("headline use" / "diagnostic only" / "rejected") with the specific conditions that fired.

### 5. Common mistakes

- **Validating the judge without validating the humans.** A judge kappa of 0.65 against humans who agree with each other at kappa 0.35 is meaningless — the humans don't have a stable signal to validate against.
- **One rater per item.** Single-rater "truth" is a label, not a reference. Three raters with a documented adjudication rule is the minimum defensible protocol.
- **Reporting only the point kappa.** Without a CI, kappa 0.55 and kappa 0.70 look similar; with a CI, one is "fair-maybe-moderate" and the other is "substantial-almost-perfect." Always ship the CI.
- **Changing the rubric mid-study.** Humans labelling under v1.0 and v1.1 of the rubric are not labelling the same task. Fix the rubric, bump the version, re-run the study.
- **Comparing judge to a single "gold" annotator.** The gold annotator may be wrong on ambiguous items. Majority-of-three with adjudication is the floor; adjudication by a rubric author is the ceiling.
- **Dropping items where the judge flagged `off_topic`.** Flagged items are categorical; count them separately. Dropping them inflates the apparent agreement on the remaining items by selecting on the outcome.
- **Letting raters see the judge output.** Raters who see the judge's verdict anchor on it (consciously or not). Blind labelling first, judge comparison second.
- **Re-running the study after seeing the numbers.** A judge configuration or rubric version that was changed in response to the agreement numbers must be validated against a *fresh* sample. Reusing the same items is p-hacking the calibration.

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires measurements to be validated against an operational context; the calibration study is the direct operationalization.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML08 Model Skewing** maps to systematic judge-vs-human disagreement on a slice: a known skew is a known attack surface.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` names the technique that exploits a documented judge bias once the study reveals one.

<!-- Local exercise context: the specific thresholds in `decision.yaml` (0.60 kappa for headline, 0.20 judge_error cap, 0.05 rubric_gap cap) are illustrative defaults that fit the `helpfulness_v1` rubric from exercise-01. Rewrite them for the domain and stakes of your own eval before adopting. -->
