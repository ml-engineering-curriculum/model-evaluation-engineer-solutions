## exercise-02 — Inter-Annotator Agreement Computation and Disagreement Analysis — Solution

### 1. Solution overview

Once a pilot or production run collects labels from multiple raters per item ([exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md)), the next job is to decide whether those labels can be trusted as a reference. "The raters agreed most of the time" is not that decision — raters agree most of the time on nearly every task, because many items are easy. The real question is whether they agree **above chance**, consistently, and *where* they disagree.

The reference answer has four deliverables:

1. A **statistic-selection policy** — a short committed rule that picks the right agreement coefficient for the task's label type (categorical, ordinal, span, continuous), number of raters, and missing-data pattern. Picking the statistic after the numbers come in is p-hacking the agreement report.
2. A **reference implementation** — a small, test-covered module that computes the selected statistic with a bootstrap confidence interval and a per-slice breakdown, pinned by seed.
3. A **disagreement audit** — a structured review of every item where fewer than a quorum of raters agreed, with each disagreement labelled as `rater_error`, `guideline_gap`, `ambiguous_item`, or `item_defect`. Unlabelled disagreements are missing data, not neutral background.
4. A **decision contract** — numeric thresholds for `publish` / `diagnose` / `fix guideline` that read off the agreement number, its CI, and the disagreement label distribution together. The three numbers are not interchangeable and must be reported together.

This maps to the NIST AI RMF `MEASURE` function, which requires measurement reliability to be documented and validated against the operational context ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML08 Model Skewing** — a slice where humans themselves do not agree is a slice where every downstream model's error signal is noise rather than truth; an attacker who finds that slice can push model behavior inside it without triggering any reliable evaluation ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Craft Adversarial Data` describes the attacker who does exactly this ([MITRE ATLAS](https://atlas.mitre.org/)).

### 2. Worked implementation

The running example is the pairwise helpfulness task from [exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md): label set `{"1", "2", "tie"}`, 3 raters per item, flags are categorical and are counted separately. The same machinery applies to absolute 1–5 scores, span annotation, or multi-label harm categories; only the coefficient changes per section 2.1.

#### 2.1 Statistic-selection policy

Commit the decision table to `agreement/policy.yaml`. The file is referenced by the analysis code; a change to the table is a code change, not a reporting opinion.

```yaml
# agreement/policy.yaml
coefficients:
  - name: percent_agreement
    always_report: true
    rationale: "Readable by non-statisticians. Never the headline; chance-correction matters."
  - name: cohen_kappa
    when:
      raters_per_item: 2
      label_type: [nominal, ordinal_short]
      missing_data: none
  - name: fleiss_kappa
    when:
      raters_per_item: ">= 3"
      label_type: [nominal, ordinal_short]
      missing_data: none
      note: "Fleiss treats rater identities as interchangeable; use Krippendorff when raters are not."
  - name: krippendorff_alpha
    when:
      raters_per_item: any
      label_type: [nominal, ordinal, interval, ratio]
      missing_data: allowed
      note: "General case. Use when raters-per-item varies across items or when the label space is ordinal/continuous."
  - name: icc_2_1
    when:
      label_type: continuous
      raters_per_item: ">= 2"
      note: "Random raters, single rating per item. Use ICC(3,1) if your raters are fixed."

interpretation_bands:
  source: "Landis & Koch 1977 convention; labels, not folklore."
  bands:
    poor:           [-1.0, 0.00]
    slight:         [0.00, 0.20]
    fair:           [0.20, 0.40]
    moderate:       [0.40, 0.60]
    substantial:    [0.60, 0.80]
    almost_perfect: [0.80, 1.00]

reporting:
  required:
    - point_estimate
    - bootstrap_ci_95
    - raw_percent_agreement
    - confusion_matrix
    - per_slice_breakdown
  bootstrap:
    n_resamples: 5000
    seed: 20261119
```

Rules worth internalizing:

- **Percent agreement is always reported, never as the headline.** Raters agreeing 80% of the time on a 3-class task where one class dominates at 70% have an unimpressive signal above chance. Report raw agreement for intuition and a chance-corrected coefficient for the decision.
- **Fleiss' kappa assumes interchangeable raters.** If you have a fixed, named panel and you care about rater identity (e.g., SME vs crowd), use Krippendorff's alpha instead; Fleiss will understate disagreement structure you can still fix.
- **Krippendorff's alpha is the general case.** It handles any level of measurement, any number of raters, and missing data. Default to it when the task does not cleanly fit Cohen / Fleiss.
- **ICC for continuous labels.** Pearson correlation looks fine while hiding a systematic offset; ICC catches both offset and scale miscalibration.

#### 2.2 Reference implementation

A minimal, dependency-free module. The goal is auditability — every number on the result card can be re-derived from this code and the committed label records.

```python
# agreement/stats.py
import math
import random
from collections import Counter
from typing import Iterable, Sequence


def percent_agreement(ratings_per_item: Sequence[Sequence[str]]) -> float:
    """Fraction of items where all raters agree. Documented primary intuition only."""
    n = len(ratings_per_item)
    if n == 0:
        return float("nan")
    return sum(1 for r in ratings_per_item if len(set(r)) == 1) / n


def fleiss_kappa(ratings_per_item: Sequence[Sequence[str]], categories: Sequence[str]) -> float:
    """Fleiss' kappa for >=3 raters, nominal labels, no missing data.

    ratings_per_item[i] is a list of labels for item i. Every item must
    have the same number of raters; items with missing ratings should be
    routed to krippendorff_alpha instead.
    """
    n = len(ratings_per_item)
    if n == 0:
        return float("nan")
    cats = {c: i for i, c in enumerate(categories)}
    N = len(categories)

    counts = [[0] * N for _ in range(n)]
    row_totals = []
    for i, labels in enumerate(ratings_per_item):
        if not labels:
            raise ValueError(f"item {i} has no ratings")
        row_totals.append(len(labels))
        for lab in labels:
            if lab not in cats:
                raise ValueError(f"item {i}: label {lab!r} not in categories")
            counts[i][cats[lab]] += 1
    # Fleiss requires the same rater count per item
    r = row_totals[0]
    if any(t != r for t in row_totals):
        raise ValueError("Fleiss requires equal raters per item; use krippendorff_alpha instead")
    if r < 2:
        raise ValueError("need at least 2 raters per item")

    # P_i: pairwise agreement proportion per item
    P_i = [sum(c * (c - 1) for c in row) / (r * (r - 1)) for row in counts]
    P_bar = sum(P_i) / n
    # Expected agreement under the marginal label distribution
    total = n * r
    p_j = [sum(counts[i][j] for i in range(n)) / total for j in range(N)]
    Pe = sum(p * p for p in p_j)
    return (P_bar - Pe) / (1 - Pe) if Pe < 1 else float("nan")


def krippendorff_alpha(
    ratings_per_item: Sequence[Sequence[str | None]],
    categories: Sequence[str],
    level: str = "nominal",
) -> float:
    """Krippendorff's alpha. Supports missing ratings (None entries).

    level in {"nominal", "ordinal", "interval"} selects the distance function.
    For nominal: delta(a, b) = 0 if a == b else 1.
    For ordinal: squared difference of category ranks.
    For interval: squared difference of numeric labels (categories must be numeric strings).
    """
    cats = list(categories)
    idx = {c: i for i, c in enumerate(cats)}

    def delta(a: str, b: str) -> float:
        if level == "nominal":
            return 0.0 if a == b else 1.0
        if level == "ordinal":
            return (idx[a] - idx[b]) ** 2
        if level == "interval":
            return (float(a) - float(b)) ** 2
        raise ValueError(f"unknown level {level!r}")

    # Observed disagreement Do
    pair_count = 0
    Do_sum = 0.0
    marg = Counter()
    for labels in ratings_per_item:
        obs = [lab for lab in labels if lab is not None]
        m = len(obs)
        if m < 2:
            continue
        for a in obs:
            marg[a] += 1
        for i in range(m):
            for j in range(m):
                if i == j:
                    continue
                Do_sum += delta(obs[i], obs[j])
        pair_count += m * (m - 1)
    if pair_count == 0:
        return float("nan")
    Do = Do_sum / pair_count

    # Expected disagreement De from the marginal
    total = sum(marg.values())
    De_sum = 0.0
    labs = list(marg.keys())
    for i in range(len(labs)):
        for j in range(len(labs)):
            if i == j:
                continue
            De_sum += marg[labs[i]] * marg[labs[j]] * delta(labs[i], labs[j])
    De = De_sum / (total * (total - 1)) if total > 1 else float("nan")

    return 1.0 - (Do / De) if De > 0 else float("nan")


def icc_2_1(ratings: Sequence[Sequence[float]]) -> float:
    """ICC(2,1) — two-way random effects, single rating.

    ratings[i] is a list of rater scores for item i; all items have the
    same number of raters. Suitable for continuous / 1--5 absolute scores.
    """
    n = len(ratings)
    if n == 0:
        return float("nan")
    k = len(ratings[0])
    if any(len(r) != k for r in ratings):
        raise ValueError("ICC(2,1) requires equal raters per item")
    grand = sum(sum(r) for r in ratings) / (n * k)
    row_means = [sum(r) / k for r in ratings]
    col_means = [sum(ratings[i][j] for i in range(n)) / n for j in range(k)]

    SST = sum((ratings[i][j] - grand) ** 2 for i in range(n) for j in range(k))
    SSB = k * sum((rm - grand) ** 2 for rm in row_means)   # between items
    SSJ = n * sum((cm - grand) ** 2 for cm in col_means)   # between raters
    SSE = SST - SSB - SSJ
    MSB = SSB / (n - 1)
    MSJ = SSJ / (k - 1) if k > 1 else 0.0
    MSE = SSE / ((n - 1) * (k - 1)) if (n - 1) * (k - 1) > 0 else float("nan")

    denom = MSB + (k - 1) * MSE + k * (MSJ - MSE) / n
    return (MSB - MSE) / denom if denom != 0 else float("nan")


def bootstrap_ci(
    ratings_per_item: Sequence[Sequence[str]],
    statistic,
    n_resamples: int = 5000,
    seed: int = 20261119,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Nonparametric bootstrap CI over items. Resamples items with replacement.

    `statistic` is a callable accepting the resampled ratings_per_item sequence.
    Seed is pinned; change it only by also changing the point estimate's seed
    reference on the result card.
    """
    rng = random.Random(seed)
    n = len(ratings_per_item)
    samples = []
    for _ in range(n_resamples):
        resample = [ratings_per_item[rng.randrange(n)] for _ in range(n)]
        try:
            samples.append(statistic(resample))
        except Exception:
            continue
    samples.sort()
    lo = samples[int(alpha / 2 * len(samples))]
    hi = samples[int((1 - alpha / 2) * len(samples))]
    return lo, hi
```

Non-obvious choices:

- **Bootstrap resamples items, not rater-item cells.** Items are the units of analysis; resampling cells would conflate two sources of noise and underestimate the CI.
- **Krippendorff is not a convenience wrapper over Fleiss.** It uses a different distance function and handles missing ratings natively; the code path is separate.
- **ICC(2,1) is the right default for 1–5 absolute labels with a non-fixed rater pool.** If the raters are a fixed, named panel and you only care about *those* raters, ICC(3,1) is correct instead; the only change is the denominator term.
- **Flags are counted separately.** The `categories` passed in are `{"1", "2", "tie"}`; items with a `refusal`/`off_topic`/`unanswerable`/`harmful_content` flag never enter the kappa computation. They are reported as a separate rate on the result card.

Example invocation and result-card schema:

```python
# agreement/report.py
from .stats import fleiss_kappa, percent_agreement, bootstrap_ci

CATS = ["1", "2", "tie"]


def report(ratings_per_item, slice_col=None):
    kappa = fleiss_kappa(ratings_per_item, CATS)
    pa = percent_agreement(ratings_per_item)
    lo, hi = bootstrap_ci(
        ratings_per_item,
        lambda r: fleiss_kappa(r, CATS),
        n_resamples=5000, seed=20261119,
    )
    return {
        "coefficient": "fleiss_kappa",
        "point": round(kappa, 3),
        "ci95": [round(lo, 3), round(hi, 3)],
        "percent_agreement": round(pa, 3),
        "n_items": len(ratings_per_item),
        "band": classify(kappa),
    }
```

The per-slice breakdown is produced by calling `report()` with the subset of items in each slice (short / medium / long response, by topic, by response length ratio, by any pilot-committed stratum). A headline number that looks fine but hides a `fair` slice at long-response-ratio is a known failure mode; the slice breakdown is the only way to catch it.

#### 2.3 Confusion matrix and marginal audit

Every agreement report ships a confusion matrix over the label set. For 3 raters per item, a convenient reduction is the *rater-pair* confusion matrix: for each item, every unordered pair of raters contributes one off-diagonal cell when they disagree. The matrix immediately exposes the structure of the disagreement:

```
                       Rater B label
                 |  1    |  2    |  tie  |
Rater A label  1 |  412  |   18  |   24  |
               2 |   22  |  389  |   31  |
               tie|  41  |   38  |  118  |
```

Reading rules:

- **Heavy off-diagonal between "1" and "2"** without going through "tie" = raters are picking opposite sides on the same items. Most likely a guideline-anchor gap, not a rater bug.
- **"tie" row underpopulated vs expected** = raters are refusing to call ties. Re-read the guideline's tie rule; this is almost always a UI / training problem, not a hard task.
- **Row/column imbalance** (one label systematically chosen more often by one rater) = per-rater skew. Report `cohen_kappa(rater_i, majority_without_i)` per rater; retrain or remove the outlier.

#### 2.4 Disagreement audit

Every item without full-rater agreement (for pairwise with 3 raters: every item that is not 3-0 on one label) is reviewed. A rubric author — not a study rater — labels each disagreement with one of:

```yaml
# agreement/disagreement_labels.yaml
labels:
  - rater_error:     "One rater misread the response or the guideline; the majority is right."
  - guideline_gap:   "The guideline does not disambiguate this item; raters are each defensible under their reading."
  - ambiguous_item:  "The item is intrinsically ambiguous (equally supportable responses, missing context)."
  - item_defect:     "The item should not be in the pool (malformed, truncated, pre-labelled, duplicated)."
```

Four numbers go on the result card alongside the kappa and CI:

- **`rater_error` fraction** — if this is high, retrain / tighten the pool.
- **`guideline_gap` fraction** — if this is non-negligible, the guideline has to change; bump the version and re-pilot.
- **`ambiguous_item` fraction** — expected, non-zero. Not a bug in the instrument; a property of the data. Decide whether to drop, re-source, or retain-with-majority.
- **`item_defect` fraction** — should be close to zero on a well-sourced pool. If it isn't, the source pipeline is leaking garbage and no agreement number from this run is trustworthy.

A kappa of 0.65 with 80% `rater_error` disagreements is very different from a kappa of 0.65 with 10% `rater_error` and 70% `ambiguous_item`. The distribution is what drives the next action, not the point estimate on its own.

#### 2.5 Decision contract

```yaml
# agreement/decision.yaml
publish_as_reference:
  require:
    - "kappa_point >= 0.60"
    - "kappa_ci_lower >= 0.50"
    - "rater_error_fraction <= 0.25"
    - "guideline_gap_fraction <= 0.05"
    - "item_defect_fraction <= 0.02"
    - "every_slice_kappa >= 0.40"       # no slice silently below 'fair'
diagnose_only:
  require:
    - "kappa_point >= 0.40"
    - "guideline_gap_fraction <= 0.15"
fix_guideline:
  when:
    - "guideline_gap_fraction > 0.15 OR any_slice_kappa < 0.20"
reject:
  when: "kappa_point < 0.20 OR item_defect_fraction > 0.10"
```

- **Publish as reference.** The labels may be used as the human reference for downstream model/judge evaluation.
- **Diagnose only.** Labels may inform internal dashboards but are not a published number.
- **Fix guideline.** The instrument itself is the problem; bump the task version and re-pilot ([exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md)) before another agreement run.
- **Reject.** Do not use; the pool, the raters, or the UI needs investigation before anything else.

### 3. Validation steps

1. **Unit tests on known fixtures.** `tests/test_stats.py` includes small hand-computed fixtures: Fleiss kappa of 1.0 on all-agree ratings, 0.0 on random-looking ratings sampled from the computed marginal, and the Krippendorff reference table from the standard textbook examples. CI fails on any drift beyond 1e-6.
2. **Statistic-selection unit test.** `tests/test_policy.py` loads `agreement/policy.yaml` and asserts that the right coefficient is picked for each of (2 raters nominal), (3 raters nominal, no missing), (3 raters nominal, missing allowed), (continuous 2+ raters). A code path that picks the wrong statistic is a reporting bug.
3. **Bootstrap determinism.** Re-running `bootstrap_ci` with the pinned seed on the same labels produces bit-identical `(lo, hi)`. If not, something upstream is nondeterministic and the CI is not reproducible.
4. **Slice breakdown completeness.** Every stratification axis declared in the upstream pilot plan appears as a per-slice row in the report. CI fails if an axis is missing — an "overall kappa only" report is a known way to hide a bad slice.
5. **Disagreement audit completeness.** Every non-unanimous item has a disagreement label. CI reports audit coverage as a percentage; `publish_as_reference` requires 100%.
6. **Flag separation check.** The headline kappa was computed over items *without* flags; the flag rate is reported separately. If a flagged item sneaks into the kappa input, the coefficient is biased by a category collapse that lost information.
7. **Confusion-matrix sanity.** For pairwise, the `tie` row and column are both populated. A matrix where raters never emit `tie` even when the item set contains ties is a UI / training bug, not a rater-quality problem; fix before re-running.
8. **Label-space enumeration pinning.** The `CATS` constant passed into `fleiss_kappa` / `krippendorff_alpha` is loaded from `task.yaml`. Hardcoding the label list in two places silently diverges the moment a label is added.

### 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Statistic is selected by a committed policy, not by inspection | 2 | `policy.yaml` exists; code loads it; a code-level test asserts the right coefficient per task shape. |
| R2 | Chance-corrected coefficient is the headline, not percent agreement | 1 | Result card leads with kappa / alpha / ICC; percent agreement is secondary. |
| R3 | Bootstrap CI accompanies every point estimate | 1 | 95% CI from pinned seed; `n_resamples >= 2000`; CI column on the result card. |
| R4 | Per-slice breakdown accompanies the headline | 1 | Every pre-committed stratum has its own row with coefficient + CI. |
| R5 | Confusion matrix is in the report | 1 | Label-by-label matrix (or rater-pair matrix) with row/column totals. |
| R6 | Disagreement audit labels every non-unanimous item | 2 | All disagreements labelled rater_error / guideline_gap / ambiguous_item / item_defect; distribution surfaced. |
| R7 | Flagged items are reported separately, not folded into kappa | 1 | Flag rate is a distinct column; headline coefficient is computed on non-flagged items. |
| R8 | A commit-level decision rule picks publish / diagnose / fix / reject | 1 | `decision.yaml` thresholds are explicit; the outcome and the specific conditions that fired are named in the memo. |

**Passing bar:** 7 / 10.

Reviewer checklist:

- [ ] The right statistic is used for the label type and rater structure (2 raters nominal → Cohen; 3+ nominal no missing → Fleiss; missing data or mixed-level → Krippendorff; continuous → ICC).
- [ ] Point estimate + 95% CI + raw agreement are all on the result card, with units.
- [ ] Every pre-committed stratum has its own agreement row; no slice silently below 0.40.
- [ ] Confusion matrix is readable; the `tie` row/column is populated when the label set includes `tie`.
- [ ] Every non-unanimous item has a disagreement audit label; coverage is 100%.
- [ ] Flagged items are reported as a separate rate, not folded into the kappa.
- [ ] Decision outcome is `publish_as_reference` / `diagnose_only` / `fix_guideline` / `reject` with the specific condition that fired.

### 5. Common mistakes

- **Percent agreement as the headline.** 80% on a dominant-class task is unimpressive; the chance-corrected coefficient is what tells you the labels carry signal.
- **Fleiss on 2 raters.** Fleiss degenerates on 2 raters and does not report the same thing Cohen does. Use Cohen when the pool has exactly 2 raters per item.
- **Fleiss when rater identities matter.** Fleiss treats raters as interchangeable; a fixed panel with real per-rater bias wants Krippendorff or a per-rater Cohen breakdown.
- **Pearson instead of ICC on continuous labels.** Pearson ignores systematic offset. Two raters who differ by a fixed +0.8 look perfectly correlated and have a poor ICC.
- **One rater per item.** No statistic can measure agreement from a single rater. If budget forces 1 rater per item, measure agreement on a replicated subset and report that explicitly.
- **Bootstrap over rater-item cells.** Resample items, not cells. Cell-level resampling mixes noise sources and understates the CI.
- **Changing the label set before computing kappa.** Collapsing `{A, B, tie}` into `{A, not-A}` mid-report inflates agreement by throwing away information. Report on the committed label set.
- **Dropping flagged items silently.** Flagged items are information. Report the flag rate; computing kappa on only the non-flagged subset is correct; *not mentioning* the drop is how a report lies by omission.
- **No slice breakdown.** The headline kappa is 0.62; the kappa on long-response-ratio items is 0.18. Aggregating hides the problem.
- **Changing the bootstrap seed between point estimate and CI.** The CI then describes a different sample than the point estimate. Pin one seed in `policy.yaml`.
- **Treating audit labels as blame.** `rater_error` is a process outcome, not a performance review. Raters who see the label distribution are the ones best positioned to improve the guideline; keep the audit internal to the task, not a staffing signal.
- **Soft-passing a slice.** Overall kappa 0.65, one slice at 0.22, ship it anyway. That slice will dominate every downstream failure the moment the model encounters it.
- **Reusing the same audit items for adjudication.** The disagreement audit informs *this* run's decision; it is not the adjudicated gold set. Building the gold set is the subject of [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md).

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires measurement reliability to be documented and validated against the operational context; chance-corrected agreement + bootstrap CI + disagreement audit together are that documentation for a labelling pipeline.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML08 Model Skewing** maps to a slice where humans cannot agree: that slice is where every downstream model's error signal is noise, and where an attacker can push behavior without tripping evaluation.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` is the technique that exploits a low-agreement slice; the per-slice breakdown is the control that surfaces one.

<!-- Local exercise context: the specific thresholds in `agreement/decision.yaml` (kappa_point >= 0.60 for publish, 0.05 guideline_gap cap, 0.02 item_defect cap, 0.40 per-slice floor), the pinned bootstrap seed (20261119), and the n_resamples default (5000) are illustrative defaults for a fresh general-purpose pairwise task. Rewrite them for the domain, stakes, and label geometry of your own task before adopting. The upstream guideline is the subject of [exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md); downstream adjudication and gold-set rotation are in [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md); the UX that enforces blinding and attention on the labels that feed into this computation is in [exercise-04](../exercise-04-side-by-side-ux-with-attention-checks/SOLUTION.md). -->
