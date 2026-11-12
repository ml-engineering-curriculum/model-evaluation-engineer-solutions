# exercise-03 — Contamination Detection Pipeline — Solution

## 1. Solution overview

The exercise asks the learner to build a **contamination detection pipeline** that flags overlap between an evaluation benchmark and a candidate training corpus (or model, if the training corpus is unavailable). Contamination inflates benchmark scores without reflecting generalization — it is the single most common reason a shipped eval becomes dishonest over time.

The reference pipeline has four stages, each with a different sensitivity / specificity trade-off:

1. **Exact match & normalized n-gram overlap** — cheap, catches verbatim copies and near-verbatim after normalization.
2. **MinHash / LSH near-duplicate detection** — catches paraphrased or lightly edited copies at corpus scale.
3. **Embedding similarity** — catches semantically equivalent items (translation, heavy paraphrase) that evade token-level checks.
4. **Behavioral / membership probes** — used when the training corpus is not directly inspectable (closed-weights models). Needs the canary design from exercise-05 to be trustworthy.

The output is a per-eval-item contamination score and a disposition (`clean`, `review`, `contaminated`), plus a written policy for what the eval does with each.

This exercise maps to the NIST AI RMF `MEASURE` function — benchmarks that leak into training violate the "valid and reliable" requirement, and the `GOVERN` function expects documented processes for catching this ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). It also connects to **ML02 Data Poisoning** on the OWASP ML Top 10 (the adversarial version of what accidental contamination does unintentionally) and to the **Verify Attack** and **ML-Enabled Product or Service** tactics on MITRE ATLAS ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/); [MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Implementation

### 2.1 Pipeline shape

```
                       eval items (benchmark)
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Stage 0: Normalize       │
                 │  - unicode NFKC          │
                 │  - lowercase, strip      │
                 │  - collapse whitespace   │
                 │  - strip markup          │
                 └──────────────┬───────────┘
                                │
      ┌─────────────────────────┼─────────────────────────┐
      ▼                         ▼                         ▼
┌────────────┐          ┌────────────────┐        ┌────────────────┐
│ Stage 1:   │          │ Stage 2:       │        │ Stage 3:       │
│ N-gram     │          │ MinHash + LSH  │        │ Embedding      │
│ overlap    │          │ Jaccard ≥ τ_m  │        │ cos ≥ τ_e      │
└────┬───────┘          └───────┬────────┘        └────────┬───────┘
     │ matches                  │ near-dupes                │ semantic
     └────────────┬─────────────┴───────────────────────────┘
                  ▼
        ┌──────────────────────────┐
        │ Stage 4 (optional):      │
        │ Behavioral probe         │
        │ (closed-weights only)    │
        └──────────────┬───────────┘
                       ▼
        ┌──────────────────────────┐
        │ Disposition engine       │
        │ clean / review / contam. │
        └──────────────────────────┘
```

Each stage writes evidence into a per-item record. A downstream reviewer can re-run the disposition logic against the evidence without re-scanning the corpus.

### 2.2 Stage 0 — normalization

Normalization controls false negatives on stage 1 and false positives on stage 3. The minimum set:

- Unicode NFKC normalization.
- Lowercase.
- Strip HTML / markdown markup.
- Collapse runs of whitespace to a single space.
- Trim.

Optional, domain-dependent:

- Strip punctuation for n-gram stage only (do **not** normalize before the embedding stage — the model may use punctuation signal).
- Replace numeric spans with a `<NUM>` token for math / tabular benchmarks (otherwise an arithmetic benchmark looks "contaminated" by any corpus containing numbers).

Normalization is per-stage. A single global normalization is a bug: what helps the n-gram stage can hurt the embedding stage.

### 2.3 Stage 1 — n-gram overlap

Choose `n` by item length. For short items (<50 tokens), `n=8` is a defensible floor; for longer items, `n=13` is the value commonly used in large-scale decontamination writeups. Record `n` in the output; different studies use different values.

For each eval item `e` and each training document `d`, compute the number of shared `n`-grams. An item is flagged if any of:

- `max_shared_ngrams(e, d) ≥ k` for some policy-chosen `k`, or
- fraction of `e`'s `n`-grams that appear in `d` ≥ `τ_n`.

Implementation — in-memory for small corpora, Bloom filter or sharded lookup for large ones:

```python
# decontaminate_ngram.py
from collections import Counter

def ngrams(tokens, n):
    return [tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]

def build_corpus_ngram_set(corpus_docs, n):
    seen = set()
    for doc in corpus_docs:
        for g in ngrams(doc.tokens, n):
            seen.add(g)
    return seen

def score_item(item, corpus_ngrams, n):
    item_grams = ngrams(item.tokens, n)
    if not item_grams:
        return 0.0, 0
    hits = sum(1 for g in item_grams if g in corpus_ngrams)
    return hits / len(item_grams), hits
```

Output per item:

```json
{
  "item_id": "qa-00142",
  "ngram_n": 13,
  "ngram_hit_frac": 0.82,
  "ngram_hit_count": 41,
  "ngram_matches": ["(top-K matched n-grams for forensics)"]
}
```

### 2.4 Stage 2 — MinHash / LSH

MinHash gives a scalable estimator of Jaccard similarity over token (or character-shingle) sets. LSH buckets similar documents together so comparison is sublinear in corpus size.

Typical configuration:

- 5-shingle or 8-shingle token windows.
- 128–256 permutation hashes.
- LSH bands tuned for a Jaccard threshold `τ_m` in `[0.5, 0.8]` depending on tolerance for paraphrase.

Flag an item if any corpus document has estimated Jaccard ≥ `τ_m`.

```python
# decontaminate_minhash.py (datasketch API shape)
from datasketch import MinHash, MinHashLSH

def mh(shingles, num_perm=128):
    m = MinHash(num_perm=num_perm)
    for s in shingles:
        m.update(s.encode("utf-8"))
    return m

def build_lsh(corpus_docs, threshold=0.7, num_perm=128):
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    for doc in corpus_docs:
        lsh.insert(doc.id, mh(doc.shingles, num_perm))
    return lsh

def near_duplicates(item, lsh, num_perm=128):
    return lsh.query(mh(item.shingles, num_perm))
```

MinHash's weakness is semantic paraphrase. "Who wrote Hamlet?" and "Which author penned the tragedy of Hamlet?" have low Jaccard and will slip through. That is stage 3.

### 2.5 Stage 3 — embedding similarity

Encode each eval item and each candidate training document with a sentence encoder (choice of model is a documented decision — the same model must be used to encode both sides). Index the corpus embeddings in an ANN index (FAISS, ScaNN, HNSW). For each eval item, retrieve the top-K neighbors; flag any neighbor with cosine similarity ≥ `τ_e`.

Choose `τ_e` empirically by **calibration against known-contaminated and known-clean pairs**. A fixed "0.9" is not a calibrated threshold; it is a guess.

Calibration protocol:

1. Hand-build a labeled set: ~100 known-contaminated pairs (paraphrases, translations of eval items) and ~100 known-clean pairs.
2. Compute cosine similarities for both populations.
3. Pick `τ_e` to hit a target false-positive rate (e.g. 5%); report the achieved true-positive rate.
4. Report `τ_e`, FPR, TPR, and the encoder model + version in the final report.

### 2.6 Stage 4 — behavioral / membership probes (closed-weights models)

When the training corpus is not available, you can only observe the model. Techniques, in rough order of trust:

- **Canary recall probe.** If the benchmark includes canary items (see exercise-05) with low-prior strings, prompt the model and check whether it emits the unique continuation. High recall means the canary was memorized, which means the corpus was in training.
- **Min-K% probability.** Score tokens of the eval item with the model and check whether the bottom-K% token log-probs are higher than you would expect for unseen text. Cite the method and the exact token budget.
- **Perplexity gap on structurally matched held-out items.** If the model's perplexity on eval items is sharply lower than on structurally matched held-out items you authored after the training cutoff, that is a contamination signal.

Behavioral probes are **evidence, not proof**. A positive result from one probe triggers a `review` disposition; it is the canary-recall probe (which uses items that were designed to be memorized if ingested) that is strong enough to trigger `contaminated` on its own. Specific thresholds for min-K% and perplexity-gap methods depend heavily on model family and tokenizer — cite the method you use and show your calibration, rather than importing numbers from this document.

### 2.7 Disposition logic

```python
# disposition.py
def dispose(record, thresholds):
    if record.ngram_hit_frac >= thresholds.ngram_hit_contam \
       or record.minhash_jaccard >= thresholds.minhash_contam \
       or record.canary_recall:
        return "contaminated"
    if record.ngram_hit_frac >= thresholds.ngram_hit_review \
       or record.minhash_jaccard >= thresholds.minhash_review \
       or record.embedding_cos >= thresholds.embedding_review \
       or record.minkpct_signal \
       or record.ppl_gap_signal:
        return "review"
    return "clean"
```

- `contaminated` items are **removed from the scored set** before any model is scored. They remain in the artifact (quarantined), with the stage that triggered removal recorded.
- `review` items go to a human. The reviewer either reclassifies to `contaminated` (and the item leaves the scored set) or to `clean` (with a one-line justification).
- `clean` items make up the scored benchmark.

Report the base rates and the removals in the eval release notes:

```
Decontamination report
  Scanned: 2,000 eval items
  Clean: 1,842 (92.1%)
  Review → clean: 73
  Review → contaminated: 24
  Contaminated by n-gram: 41
  Contaminated by MinHash: 12
  Contaminated by canary recall: 8
  Final scored set: 1,915 items
```

## 3. Validation steps

1. **Injected-positive test.** Insert 50 known-contaminated items (verbatim duplicates, paraphrases, translations) into the eval set. The pipeline must flag all verbatim items in stage 1, all paraphrased items by stage 2 or 3, and translations by stage 3. Report the recall of this synthetic set.
2. **Injected-negative test.** Insert 50 items known to be topically similar but *not* overlapping with the training corpus (e.g. items authored after the corpus cutoff). Report the false-positive rate. A pipeline that flags everything is useless.
3. **Threshold calibration audit.** For `τ_m` and `τ_e`, show the calibration ROC and the chosen operating point. "We picked 0.7" with no curve fails this check.
4. **Normalization independence.** Each stage records the normalization it applied. Changing normalization in one stage must not silently change results in another.
5. **Re-runnability.** The pipeline writes evidence sufficient to re-derive the disposition without re-scanning the corpus. A reviewer can change `thresholds.yaml` and re-run only `disposition.py` to see the new counts.
6. **Null-corpus test.** Run the pipeline with an empty training corpus. Every item must come back `clean`. Any `review`/`contaminated` with an empty corpus is a bug in the pipeline.
7. **Negative canary test.** When behavioral probes are in use, include canaries that were *not* in training. The model must not "recall" them. If it does, your canary design is leaky (see exercise-05).

## 4. Rubric

Scored out of 12 (the extra two points reflect the breadth of methods required).

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Pipeline has at least three independent detection stages | 2 | N-gram + near-duplicate + embedding (or a documented reason to skip one). |
| R2 | Normalization is per-stage and documented | 1 | Each stage declares its normalization in the output record. |
| R3 | N-gram stage reports `n`, hit fraction, and hit count | 1 | Output rows show all three. |
| R4 | Near-duplicate stage is sublinear and tunable | 1 | MinHash+LSH or equivalent; `τ_m` and permutation count declared. |
| R5 | Embedding threshold is calibrated | 2 | Labeled calibration set + ROC + chosen operating point + achieved FPR/TPR. |
| R6 | Disposition policy is written down and deterministic | 1 | `disposition.py` or equivalent; thresholds live in a config, not in code. |
| R7 | Contaminated items are quarantined, not deleted | 1 | Quarantine file retained; scored set documented separately. |
| R8 | Behavioral probes labeled as evidence, not proof | 1 | Report wording is calibrated; only canary-recall can trigger `contaminated` solo. |
| R9 | Injected-positive and injected-negative tests are run | 2 | Numbers reported in release notes; pipeline fails loudly if recall drops. |

**Passing bar:** 8 / 12. R5 and R9 are mandatory.

### Review checklist

- [ ] Each stage has a documented normalization and threshold.
- [ ] Thresholds live in a config file, not inline.
- [ ] Calibration evidence is committed.
- [ ] Quarantine set is present and non-empty on realistic corpora.
- [ ] Injected-positive recall ≥ team-declared floor.
- [ ] Injected-negative FPR ≤ team-declared ceiling.
- [ ] Encoder model and version are pinned.

## 5. Common mistakes

- **Single-stage pipelines.** N-gram-only misses paraphrase. Embedding-only is noisy on short items. Use at least two stages.
- **Global normalization.** Stripping punctuation before embedding hurts recall; keeping markup before n-gram inflates mismatch rates. Normalize per stage.
- **Uncalibrated embedding thresholds.** "cos ≥ 0.9" with no calibration either misses most paraphrases or flags everything, and no one will know which.
- **Treating behavioral probes as proof.** A perplexity gap suggests, a canary recalls. Do not demote an item to `contaminated` on perplexity alone.
- **Scoring before decontaminating.** The scored set must be the post-decontamination set. If you report scores on "the full eval" without a side-by-side post-decon number, the headline score is suspect.
- **Not quarantining removals.** A reviewer needs to be able to inspect what was removed and why. Silently deleting items from the scored set erases the audit trail.
- **Hard-coded thresholds in code.** Thresholds change over time and per corpus; keep them in a config and version them with the eval release.
- **No injected-positive test.** Without it, you have a pipeline that runs but no claim that it works.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. `MEASURE` 2.3 (accuracy / robustness / reliability) and `MEASURE` 2.9 (interpretability / documentation of measurement limitations) justify explicit decontamination and documented thresholds.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML02 (Data Poisoning) is the adversarial dual of contamination; the same detection surface is relevant.
- MITRE ATLAS — <https://atlas.mitre.org/>. ATLAS's Attack Staging and Verify Attack tactics document why an adversary cares about which items a model has seen; the detection posture is the same whether the overlap is malicious or accidental.
- datasketch — <https://ekzhu.com/datasketch/>. Reference implementation for MinHash+LSH used in the stage 2 snippet.

<!-- Local exercise context: the specific `n`, `τ_m`, and `τ_e` values shown are illustrative. Any real pipeline should pick thresholds based on its calibration data and should report both the thresholds and the calibration evidence alongside the eval. -->
