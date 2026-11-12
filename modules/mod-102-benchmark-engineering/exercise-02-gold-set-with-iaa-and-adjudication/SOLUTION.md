# exercise-02 — Gold Set With IAA and Adjudication — Solution

## 1. Solution overview

The exercise asks the learner to turn raw human labels into a **defensible gold set** for a benchmark. The reference answer walks through five artifacts:

1. A **label schema + guidelines** tight enough to reduce legitimate disagreement.
2. A **sampling and double-labeling plan** (who labels what, how many annotators per item).
3. An **inter-annotator agreement (IAA)** computation with the right coefficient for the label type, reported on the right subset.
4. An **adjudication protocol** that resolves disagreements without laundering them.
5. A **gold-set release checklist** that makes the artifact auditable before it is used to score any model.

The exercise is fundamentally about measurement validity — the NIST AI RMF `MEASURE` function asks that evaluation data be "representative, valid, and reliable" and that known limitations be documented ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). A gold set that was labeled by one person with no agreement check is neither reliable nor documented.

It also hardens two classes of eval-time risk called out by OWASP ML Top 10 and MITRE ATLAS: **ML08 Model Skewing** (biased labels → biased accept/reject decisions) and **data integrity** attacks under the ATLAS `ML Attack Staging` tactic — both are much harder to detect without a double-labeled gold set that you can re-audit later ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/); [MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Implementation

### 2.1 Label schema and guidelines

Running example: a factuality benchmark where each item is a (claim, supporting_passage) pair and the label is one of:

- `supported` — the passage entails the claim.
- `contradicted` — the passage entails the negation of the claim.
- `not_enough_info` — the passage neither entails nor contradicts the claim.

The schema is a **three-way nominal** label. This matters because it determines the right IAA coefficient (see §2.3).

The guidelines doc must at minimum cover:

- One-sentence definition per class.
- Two to four worked positive examples per class.
- A dedicated "edge cases" section (e.g. "if the passage says 'studies suggest X', treat as `not_enough_info` unless the claim uses hedged language").
- An escalation path for cases the guidelines do not cover (route to adjudicator, do not guess).

Guideline churn should be tracked: every edit bumps a version string. Items labeled under an older version are re-opened or explicitly marked as "label under v1.2."

### 2.2 Sampling and double-labeling plan

For a benchmark of `N` target items:

| Pool | Purpose | Size | Annotators per item |
|---|---|---|---|
| Pilot | Calibrate the guidelines | ~50 items | 3 (all annotators) |
| Calibration | Compute IAA on a stable sample | ~10–20% of `N`, min 100 items | 2+ (random pairs or all annotators on a fixed subset) |
| Production | Bulk labeling | Remainder | 1 (with adjudication-triggered re-labeling) |

The reference answer defends the small *double-labeled* subset: you do not need every item double-labeled to compute IAA — a representative calibration subset is enough, and the cost scales linearly with annotator hours. The pilot is for the *guidelines*; the calibration is for the *coefficient*; production is for the *dataset*.

A worked example on `N=1000`:

```yaml
pilot: 50 items × 3 annotators = 150 labels
calibration: 150 items × 2 annotators = 300 labels
production: 850 items × 1 annotator = 850 labels (+ re-labels from adjudication)
total_labels: ~1300 (vs. 3000 if we double-labeled everything)
```

### 2.3 Choosing and computing IAA

Choose the coefficient by **label type** and **number of annotators**:

| Label structure | Two annotators | Three+ annotators |
|---|---|---|
| Binary / nominal | Cohen's κ | Fleiss' κ or Krippendorff's α (nominal) |
| Ordinal (e.g. Likert 1–5) | Weighted Cohen's κ (quadratic) | Krippendorff's α (ordinal) |
| Interval / continuous | Pearson / ICC | Krippendorff's α (interval) or ICC |
| Any, with missing labels | — | Krippendorff's α (handles missing cleanly) |

For the factuality example — three-way nominal, two annotators per item — the right coefficient is **Cohen's κ**. If more than two annotators or if some items have missing labels, prefer **Krippendorff's α**.

#### Worked calculation — Cohen's κ

Suppose on the 150-item calibration subset the confusion matrix between Annotator A and Annotator B is:

|  | B: supported | B: contradicted | B: not_enough_info | Row total |
|---|---|---|---|---|
| **A: supported** | 60 | 2 | 8 | 70 |
| **A: contradicted** | 3 | 35 | 7 | 45 |
| **A: not_enough_info** | 5 | 5 | 25 | 35 |
| **Col total** | 68 | 42 | 40 | 150 |

Observed agreement `p_o`:

```
p_o = (60 + 35 + 25) / 150 = 120 / 150 = 0.800
```

Expected agreement `p_e` from the marginals:

```
p_e = (70/150)·(68/150) + (45/150)·(42/150) + (35/150)·(40/150)
    = 0.4667·0.4533 + 0.3000·0.2800 + 0.2333·0.2667
    = 0.2115 + 0.0840 + 0.0622
    = 0.3577
```

Cohen's κ:

```
κ = (p_o − p_e) / (1 − p_e)
  = (0.800 − 0.3577) / (1 − 0.3577)
  = 0.4423 / 0.6423
  = 0.6886
```

Report κ with a **bootstrap CI** (resample items with replacement, recompute κ, take the 2.5 / 97.5 percentiles). A single-point κ with no interval is not an agreement measurement.

#### Reporting

Minimum reportable:

- Coefficient name and variant (e.g. "Cohen's κ, unweighted").
- Point estimate with 95% CI.
- `n` of the calibration subset.
- Per-class breakdown (sometimes overall κ looks fine but a rare class has κ near zero).
- A sentence on what label structure forced the coefficient choice.

Interpretation benchmarks commonly used in practice (Landis & Koch, 1977):

| κ range | Verbal label |
|---|---|
| < 0.00 | Poor |
| 0.00–0.20 | Slight |
| 0.21–0.40 | Fair |
| 0.41–0.60 | Moderate |
| 0.61–0.80 | Substantial |
| 0.81–1.00 | Almost perfect |

These are heuristics, not thresholds. Treat them as a floor for *when to worry*, not a license to ship. The Landis & Koch ranges are widely cited and widely critiqued; name the ranges you are using and acknowledge the critique rather than present them as objective thresholds.

### 2.4 Adjudication protocol

The adjudication protocol is a **written** rule, not a preference.

**Trigger.** Any item where the two annotators disagree goes to adjudication. (Optional: borderline items that *agree* on a rare class can also be sampled into adjudication as a sanity check.)

**Adjudicator.** A third annotator who is senior or has passed a calibration cutoff on the pilot set. Blind to the two prior labels until they commit theirs.

**Procedure.**

1. Adjudicator labels the item independently (not shown prior labels).
2. If the adjudicator's label matches one of the two originals → that label becomes the gold.
3. If the adjudicator's label matches neither → open a *guideline* ticket, do not silently pick one. Either:
   - the item is genuinely ambiguous and should be dropped (record the reason), or
   - the guidelines are missing a case → update them, re-open earlier items that depended on the same rule, bump the guidelines version.

**Forbidden shortcuts.**

- Taking the majority of the three without the independence step. This discards the information that the adjudicator is uncertain.
- Asking the adjudicator to "pick one" when they want to open a guideline ticket. That suppresses construct-validity bugs.
- Deleting disagreed items silently. Every dropped item gets a one-line reason in the release notes.

### 2.5 Release checklist

A gold set is not ready to be imported into an evaluator until all of the following are committed:

- `guidelines.md` with version string.
- `labels.jsonl` with `{item_id, label, annotator_ids, adjudicator_id?, guideline_version}` per row.
- `iaa_report.md` with coefficient, variant, point estimate, 95% CI, per-class κ, calibration sample size.
- `adjudication_log.jsonl` with one row per adjudicated item: `{item_id, original_labels, adjudicated_label, outcome, guideline_ticket?}`.
- `dropped_items.jsonl` with `{item_id, reason}` for items removed during adjudication.
- `annotator_demographics.md` (coarse, non-identifying) — the NIST AI RMF `MEASURE` guidance asks that label-source characteristics be documented when they may affect validity.

## 3. Validation steps

1. **Recompute κ from raw labels.** A reviewer should be able to rebuild the calibration confusion matrix and re-derive κ from `labels.jsonl` alone. If they can't, the report is not verifiable.
2. **Per-class κ check.** For each label class, κ computed on the one-vs-rest collapse should be reported. A high overall κ can hide a near-zero κ on the minority class.
3. **Bootstrap CI sanity.** Lower bound of the 95% CI should be above the "slight / fair" boundary the team committed to. If the lower bound is below the floor, the gold set is not yet shippable — add more training, more calibration, or tighter guidelines.
4. **Adjudication closure.** Every item flagged for adjudication appears in `adjudication_log.jsonl` with a terminal state (`gold_assigned`, `dropped`, or `pending`). No items should be `pending` at release.
5. **Guideline-ticket back-pressure.** Every ticket opened during adjudication is either closed with a guidelines edit + re-label sweep, or marked "won't fix" with a reason. Open tickets at release time are a blocker.
6. **Negative test — label-flip audit.** Deliberately flip 5% of labels on a copy of the calibration subset and recompute κ. κ should drop materially. If it doesn't, the IAA pipeline is not measuring what the report claims.

## 4. Rubric

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Guidelines are versioned and include edge cases | 1 | `guidelines.md` has a version string, at least one "edge cases" section, and a changelog. |
| R2 | Sampling plan separates pilot / calibration / production | 1 | Sizes and annotator counts are declared and justified. |
| R3 | Correct IAA coefficient for the label structure | 2 | Coefficient choice is defended against the table in §2.3; variant is named explicitly. |
| R4 | κ reported with 95% CI, per-class breakdown, sample size | 1 | `iaa_report.md` has all three. Point estimate alone loses this point. |
| R5 | Adjudication is independent and documented | 2 | Adjudicator labels blind; log shows `{original_labels, adjudicated_label, outcome}` per item. |
| R6 | Adjudication can re-open guidelines | 1 | At least one guideline ticket exists OR the plan declares what triggers one. |
| R7 | Dropped items have per-item reasons | 1 | `dropped_items.jsonl` lists each with a reason; "ambiguous" alone is not enough. |
| R8 | Recomputability | 1 | A reviewer can regenerate `iaa_report.md` from raw labels using a committed script. |

**Passing bar:** 7 / 10. R3 and R5 are mandatory — either failing drops the submission below passing regardless of total.

### Review checklist

- [ ] Coefficient choice matches label structure.
- [ ] CI and `n` are reported.
- [ ] Per-class κ is reported.
- [ ] Adjudication was blind to prior labels.
- [ ] Dropped items have reasons.
- [ ] Re-computation script exists and runs.

## 5. Common mistakes

- **Reporting percent agreement as IAA.** Percent agreement ignores chance and inflates on skewed label distributions. If three classes are 90/5/5, naive 90% agreement can coexist with κ near zero.
- **Using Cohen's κ with more than two annotators.** Cohen's κ is a two-rater coefficient. For more than two raters, use Fleiss' κ or Krippendorff's α.
- **Using nominal κ on ordinal labels.** If labels are Likert-scaled, an "off by one" disagreement should count less than "off by four." Use weighted κ or Krippendorff's α with an ordinal distance.
- **Averaging κ across per-item pairs.** κ is not the mean of per-item agreements; it is a function of the joint distribution. Recompute on the pooled confusion matrix.
- **Computing IAA on the adjudicated labels.** The adjudicated labels are, by construction, in agreement. IAA must be reported on the *pre-adjudication* calibration subset.
- **Letting the adjudicator see prior labels.** This collapses adjudication into "tie-break" and loses the independence signal.
- **Silently dropping disagreed items.** The drop set is a dataset in its own right; publish it and its reasons.
- **No CI.** A κ of 0.70 with CI [0.45, 0.85] is a different artifact than κ 0.70 with CI [0.68, 0.72]. Report both ends.
- **Treating the Landis & Koch bands as thresholds.** They are rough heuristics. The team must set and defend its own floor.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function motivates representative, reliable, documented evaluation data; `GOVERN` motivates the written adjudication protocol as a policy.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML08 (Model Skewing) is the production-side failure that unchecked label bias causes.
- MITRE ATLAS — <https://atlas.mitre.org/>. ML Attack Staging and Data Manipulation tactics explain why gold sets themselves are an attack target; a documented adjudication log is forensic evidence.

<!-- Local exercise context: the three-way factuality label scheme and the κ worked example are illustrative. Any real benchmark should pick coefficients and interpretation bands with its own domain in mind rather than copying these numbers. -->
