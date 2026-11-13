# exercise-05 — Regression and Ranking Eval Suite — Solution

## 1. Solution overview

The exercise asks the learner to build a **regression and ranking evaluation suite** — the eval pipeline for non-classification tasks where the output is either a numeric prediction (regression) or an ordered list (ranking / retrieval). Classification metrics do not transfer: MAE is not accuracy, NDCG is not F1, and most "aggregate" numbers in these domains hide the thing you shipped the eval to catch.

The reference answer has six pieces:

1. A **task taxonomy** — regression vs ranking, and the sub-kinds within each that pick different metrics.
2. A **regression metric set** — central tendency, error distribution, calibration of intervals, and a residual diagnostic.
3. A **ranking metric set** — a top-heavy metric, a full-order metric, and a per-query (not per-item) aggregation rule.
4. A **slice and segmentation plan** — reusing the dashboard from exercise-01, with task-specific additions.
5. A **statistical-significance protocol** — bootstrap CIs on aggregate metrics, paired comparisons across models, and a minimum-detectable-effect floor.
6. A **ship / rollback gate** — the written rules that decide whether a candidate model replaces the champion.

This maps to the NIST AI RMF `MEASURE` function, which asks for metrics that are "valid, reliable, and relevant" — in regression and ranking, that means rejecting single-number scorecards in favor of metrics that capture the error distribution and the per-query / per-slice variance ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial surface is OWASP ML Top 10 **ML09 Output Integrity Attack** — regression and ranking outputs feed downstream pricing, routing, retrieval, and recommendation; an attacker who skews the output distribution causes harm that only a distribution-aware eval will detect ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS's `Craft Adversarial Data` and `Evade ML Model` tactics describe the attack patterns the per-slice regression / ranking suite is designed to surface ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Implementation

### 2.1 Task taxonomy

Regression and ranking sit under a shared suite, but the metric set changes depending on the sub-kind.

| Task kind | Examples | Dominant metric kind |
|---|---|---|
| **Point regression** (symmetric) | Price forecast, latency prediction, demand prediction | MAE + per-percentile error; RMSE if the loss function trained for squared error. |
| **Point regression** (asymmetric) | Over-provisioning cost ≠ under-provisioning cost | Quantile loss at the policy-chosen quantile(s); report both sides of the error. |
| **Interval / distributional regression** | Uncertainty-aware forecasting | Pinball loss per quantile; coverage of the predicted interval; sharpness. |
| **Pointwise ranking** | Click-through score per item | Pointwise MAE/MSE on the score, then a top-k check. |
| **Pairwise ranking** | Learning-to-rank for search | AUC-style pairwise accuracy; fraction of pairs correctly ordered within a query. |
| **Listwise ranking** | Search, recommendation, retrieval | NDCG@k, MAP@k, MRR; coverage and fairness-of-exposure metrics as secondary. |

Write the sub-kind down in the suite config. Mixing sub-kinds in one headline metric is the single largest source of confusion in this exercise.

### 2.2 Regression metric set

A defensible regression report has **four** parts, not one:

**P1 Central tendency.** MAE for robustness, RMSE if the model was trained against squared loss. Report both unless a strong reason to drop one is on paper; they answer different questions and often move together, but not always.

**P2 Error distribution.** Percentiles of the signed residual: `p05`, `p25`, `p50` (median), `p75`, `p95`. A model with great MAE can have catastrophic p99 errors; a model with mediocre MAE but tight tails may be the right choice for a cost-sensitive consumer. Report mean and median residual to surface bias.

**P3 Interval calibration** (if the model emits intervals or quantiles). Pinball loss per quantile; empirical coverage of the nominal `(1-α)` interval; sharpness (mean interval width). A model whose "95% interval" covers 71% of truths is lying about its uncertainty, which is an ML09-shaped harm.

**P4 Residual diagnostics.** At minimum: a residual-vs-prediction plot for heteroscedasticity, a residual-vs-feature plot for drift on the dominant features, and a per-slice bias check. If residuals are not zero-mean on a slice, the model is systematically wrong there (not just noisier).

Minimum table:

```
Regression report — price-forecast-model@v3
             n       MAE       RMSE      bias (mean resid.)   p05        p50        p95
aggregate    74312   $4.12     $7.80     +$0.08               -$9.4      +$0.2      +$11.1
region_eu    18422   $4.80     $9.12     -$0.42  ← bias       -$11.1     -$0.5      +$9.8
region_apac   7104   $5.60     $11.4     +$1.10  ← bias       -$6.4      +$1.0      +$17.8  ← widening tail
long_horizon  4020   $9.30     $21.2     +$3.20                -$8.2      +$2.1      +$47.3  ← catastrophic tail
```

Supporting plots (one PNG per row drill-down): residual histogram, residual-vs-prediction, residual-vs-top-3-features, QQ-plot against a normal.

Report one summary scalar — MAE — but gate on the tails. In regression, a model whose mean improves while its tail worsens often loses money overall.

### 2.3 Ranking metric set

Ranking metrics live or die by three choices:

- **Per-query aggregation.** All ranking metrics are *per query*; the dataset metric is a mean (or trimmed mean) across queries. Compute the metric per query, then aggregate — never the other way around.
- **Cutoff k.** A top-heavy metric needs a cutoff that reflects the user experience: `k=10` for an all-screen search page, `k=3` for a narrow recommendation strip, `k=1` for voice. Pick one as the headline and report two or three others for context.
- **Gain definition.** For NDCG, record the relevance-to-gain mapping (binary, graded 0–3, graded 0–4) and the log-base for discounting. Different conventions produce incomparable numbers.

A defensible ranking report has:

- **NDCG@k** as the headline when graded relevance is available.
- **MAP@k** as a binary-relevance alternative; also robust to noisy graded labels.
- **MRR** for "first hit matters" use cases (voice, lookup).
- **Hit@k / Recall@k** for retrieval-flavored tasks.
- **Precision@1** as a sanity read for "top-one" quality.
- **Coverage** of the catalog across top-k (what fraction of items ever appear).
- **Per-query metric distribution** — median and p05 across queries — not only the mean. A model whose mean NDCG improves while the p05 collapses is losing its tail queries.

Minimum table:

```
Ranking report — search-ranker@v2
                            n_queries   NDCG@10 mean (95% CI)    NDCG@10 p05   MAP@10   MRR     Coverage@10
aggregate                    12480      0.462 (0.457, 0.466)     0.17          0.398    0.612   0.31
head_queries                  2400      0.591 (0.582, 0.600)     0.28          0.502    0.751   0.12
long_tail_queries             6200      0.411 (0.403, 0.418)     0.09          0.342    0.558   0.46
queries_with_1_relevant       3100      0.388 (0.378, 0.398)     0.00          0.388    0.561   0.19
```

### 2.4 Slices and segmentation

Reuse the dashboard taxonomy from exercise-01. Task-specific additions:

- **Regression.** Slice by predicted-value bucket. Models often have very different errors at the low and high ends of the range (log-normal targets are a classic case).
- **Regression.** Slice by horizon or input-recency. Forecasts degrade with horizon; a model that improves on the 1-day slice while regressing on the 30-day slice is a different product than the headline suggests.
- **Ranking.** Slice by query length, query frequency bucket (head vs torso vs tail), and number of relevant items per query.
- **Ranking.** Slice by position-in-results to surface position bias in training labels: a ranker that is only good at reproducing the prior ranker is a silent copy.

Per-slice floors on `n` still apply. A ranking slice with fewer than ~300 queries will not pin NDCG@10 to a stable number.

### 2.5 Statistical significance

Two protocols:

- **Aggregate CI.** Bootstrap 10,000 resamples of the eval set (resample queries for ranking, items for regression). Report the 95% CI on every headline metric.
- **Paired comparison.** When comparing two models on the same eval set, use a **paired** bootstrap: resample the eval set once, compute both metrics, take the delta, repeat. Report the CI of the delta. A positive delta whose 95% CI crosses zero is not a shipping decision.

A minimum-detectable-effect (MDE) floor: before running the comparison, pre-register the MDE you need to see to call a win, derived from the CI width on the current champion. Shipping a model whose delta is below the MDE is ships-by-noise.

### 2.6 Ship / rollback gate

Three gates run against the suite output. All three must pass:

- **Aggregate gate.** Candidate's headline metric is above the champion's within the MDE, with a paired-bootstrap CI that excludes zero on the correct side.
- **Slice gate.** No slice on the dashboard regresses beyond a documented floor. "Average improves" is not a license to crash a slice.
- **Distribution gate.** For regression, the p95 of signed residuals does not worsen beyond a documented floor. For ranking, the p05 of per-query NDCG does not worsen beyond a documented floor. Mean-improves-tail-worsens is the failure mode this gate catches.

Rollback: committing the eval artifact that produced the shipping decision is the rollback contract. The next release's eval comparison is against this blessed artifact, not a re-run.

### 2.7 Minimal reference implementation

```python
# regression_eval.py
import numpy as np

def regression_report(y_true, y_pred, slices=None):
    err = y_pred - y_true
    pct = np.percentile(err, [5, 25, 50, 75, 95])
    out = {
        "n": len(y_true),
        "mae": float(np.mean(np.abs(err))),
        "rmse": float(np.sqrt(np.mean(err ** 2))),
        "bias_mean_resid": float(err.mean()),
        "p05": float(pct[0]), "p25": float(pct[1]), "p50": float(pct[2]),
        "p75": float(pct[3]), "p95": float(pct[4]),
    }
    return out

def pinball_loss(y_true, q_pred, q):
    e = y_true - q_pred
    return float(np.mean(np.maximum(q * e, (q - 1) * e)))

def interval_coverage(y_true, lower, upper):
    return float(((y_true >= lower) & (y_true <= upper)).mean())


# ranking_eval.py
def dcg_at_k(rel, k):
    rel = np.asarray(rel)[:k]
    if rel.size == 0:
        return 0.0
    return float(np.sum((2 ** rel - 1) / np.log2(np.arange(2, rel.size + 2))))

def ndcg_at_k(rel, k):
    ideal = sorted(rel, reverse=True)
    idcg = dcg_at_k(ideal, k)
    return 0.0 if idcg == 0 else dcg_at_k(rel, k) / idcg

def per_query_ndcg(queries, k):
    # queries: iterable of (query_id, relevance_scores_in_predicted_order)
    return {qid: ndcg_at_k(rel, k) for qid, rel in queries}

def paired_bootstrap_delta(metric_a, metric_b, resample_groups, n_boot=10_000, seed=0):
    rng = np.random.default_rng(seed)
    groups = np.asarray(resample_groups)
    unique_groups = np.unique(groups)
    deltas = np.empty(n_boot)
    for i in range(n_boot):
        g = rng.choice(unique_groups, size=len(unique_groups), replace=True)
        mask = np.isin(groups, g)
        deltas[i] = np.mean(metric_a[mask]) - np.mean(metric_b[mask])
    lo, hi = np.quantile(deltas, [0.025, 0.975])
    return float(deltas.mean()), float(lo), float(hi)
```

## 3. Validation steps

1. **Per-query aggregation.** Confirm every ranking metric is computed per query first, then aggregated. The dataset-level mean must equal the mean of the per-query values; if they differ, the aggregation is being done on items instead of on queries.
2. **Determinism.** Rerun the suite twice with the same eval artifact and seed. Every number is byte-identical. If CIs move, the bootstrap seed is unpinned.
3. **Slice coverage.** Sum the slice counts for a partitioning subset and confirm they equal the aggregate `n`. Hidden slices mean hidden errors.
4. **Paired bootstrap check.** Run a paired bootstrap against the same model twice and confirm the delta CI is symmetric around zero (same data, same model → no signal). If it is not, the resampling grouping is wrong.
5. **Tail check.** Compare p95 of residuals (regression) or p05 of per-query NDCG (ranking) between the champion and the candidate. Confirm the distribution gate fires when the tail worsens by more than the floor, even if the mean improves.
6. **Interval calibration.** For an interval-regression model, confirm empirical coverage of the nominal `(1-α)` interval is within a documented tolerance. A nominal 95% interval that covers 70% is an interval-integrity bug.
7. **Position-bias sanity.** For ranking, train a model only on the labels of the previous ranker; confirm the suite catches this (coverage@k shrinks, long-tail NDCG collapses, overall mean may look fine). If the gate does not fire, position bias will not be caught in production.
8. **Adversarial shift.** Add a +10% drift to a feature that affects a specific slice. Confirm the slice gate and distribution gate catch it. This is the ML09 / ATLAS detection check.

## 4. Rubric

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Task kind is named and the metric set is appropriate | 1 | Report labels the sub-kind (point-symmetric regression, listwise ranking, etc.) and selects metrics from the matching row of the taxonomy. |
| R2 | Regression report includes central tendency, distribution, and bias | 2 | MAE/RMSE, p05–p95 percentiles of signed residuals, and the mean residual are all present. |
| R3 | Ranking metrics are computed per-query, then aggregated | 2 | The per-query vector is stored; the aggregate equals its mean (or trimmed mean); cutoff `k` is named. |
| R4 | Interval calibration or quantile loss where applicable | 1 | For interval or quantile regression, empirical coverage and pinball loss are reported; nominal vs empirical coverage appears in the report. |
| R5 | Slice dashboard covers task-specific slices | 1 | Regression: predicted-value-bucket, horizon. Ranking: query-frequency, query-length, relevant-items-per-query. |
| R6 | Paired-bootstrap CI for the candidate-vs-champion delta | 1 | Delta CI is reported; a positive delta whose CI crosses zero is explicitly not shipped. |
| R7 | Distribution gate on the tail | 1 | A gate exists on p95 residual (regression) or p05 per-query NDCG (ranking) and is enforced before ship. |
| R8 | Pre-registered MDE and committed rollback artifact | 1 | MDE is documented in the suite config; the blessed eval artifact is referenced in the ship decision for future rollback comparison. |

**Passing bar:** 7 / 10.

### Review checklist (for a maintainer)

- [ ] Task sub-kind is labeled in the suite config.
- [ ] Per-query vectors (not just aggregate scalars) are committed so paired comparisons can be rerun.
- [ ] NDCG's gain mapping and log base are specified in the config and the report.
- [ ] Residual-vs-prediction and residual-vs-feature plots are in the report, not only tables.
- [ ] A slice gate and a distribution gate are both in the ship rules, not only an aggregate gate.
- [ ] The rollback artifact is cited in the ship decision.

## 5. Common mistakes

- **Reporting only MAE (or only RMSE).** Aggregate central tendency hides catastrophic tails. Report the percentile distribution of signed residuals.
- **Reporting the mean without a CI.** A 1% mean improvement on 500 items is not a decision; it is a coin flip.
- **Aggregating ranking metrics over items, not queries.** NDCG computed over a flattened item list is not NDCG. Compute per query, aggregate across queries.
- **Not pinning the NDCG gain mapping and log base.** Two reports with different conventions are not comparable, and the comparison is always done anyway.
- **Choosing `k` after seeing the metric.** The cutoff is a product decision, not a knob that tunes the win.
- **Trusting nominal interval coverage.** A model's "95% interval" is only 95% if the empirical coverage says so; measure it.
- **Position bias in ranking labels.** A ranker trained on prior-ranker clicks may be a silent copy; the coverage@k and long-tail slice are what detect this.
- **No MDE.** Shipping on a positive delta with a CI that crosses zero is noise-chasing; the next ship against the same baseline will often reverse the "win."
- **No distribution gate.** Mean-improves-tail-worsens is the most common silent regression in these suites.
- **No adversarial slice.** ML09 / ATLAS drift leaves exactly the signatures the distribution and slice gates catch; without an adversarial slice the gate is not exercised.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires metrics that are valid, reliable, and relevant to the context of use; distribution-aware metrics and per-query aggregation are how those requirements get implemented for regression and ranking.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML09 Output Integrity Attack describes adversaries skewing regression and ranking outputs; the distribution and slice gates in this suite are the detection surface.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` and `Evade ML Model` describe the attacker behavior the per-slice and tail gates are designed to catch; the suite is the defender's instrumented view of the same surface.

<!-- Local exercise context: the sample metric tables (price-forecast-model@v3, search-ranker@v2) and the ~300-query slice floor are illustrative defaults. Real metric choices, cutoffs, gain mappings, and slice floors must be derived from the specific deployment's product context, label budget, and consumer sensitivity to tail errors. -->
