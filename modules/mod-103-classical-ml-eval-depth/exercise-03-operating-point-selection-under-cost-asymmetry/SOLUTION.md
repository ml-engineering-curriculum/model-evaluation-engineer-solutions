# exercise-03 — Operating Point Selection Under Cost Asymmetry — Solution

## 1. Solution overview

The exercise asks the learner to pick a **classification threshold** when the two error kinds carry different costs, and to defend that choice with evidence a reviewer can replay. The reference answer has five pieces:

1. A **cost model** — the dollar (or utility) matrix for the four confusion-matrix cells, and the written assumptions behind each cell's number.
2. A **score curve** — ROC and precision-recall curves drawn from the eval set, with the candidate thresholds marked.
3. An **expected-cost sweep** — expected cost as a function of threshold, with the minimum identified and its CI.
4. A **chosen operating point** — the threshold shipped, its slice-level verification, and the review path for changing it.
5. A **monitoring plan** — how the operating point is re-verified under drift and when it must be re-derived rather than just re-measured.

This maps to the NIST AI RMF `MEASURE` and `MANAGE` functions: `MEASURE` because the operating point is a committed measurement decision, and `MANAGE` because the chosen point must be governed — re-reviewed on drift, rolled back, and tied to who approved it ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). Cost-asymmetric thresholds are the direct countermeasure to OWASP ML Top 10 **ML09 Output Integrity Attack** (an attacker who shifts the score distribution causes false negatives or false positives whose cost the operating point was chosen against) and are the detection surface MITRE ATLAS's `Evade ML Model` and `Verify Attack` tactics describe ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/); [MITRE ATLAS](https://atlas.mitre.org/)).

The one-sentence rule the whole exercise reduces to: **ship the threshold that minimizes expected cost on the held-out set, with a CI, and recompute it when any input to the cost matrix or score distribution changes.**

## 2. Implementation

### 2.1 Cost model

Write the matrix down. "Precision matters more than recall" is not a cost model; a table of numbers is.

| Cell | Count | Unit cost | Source of the number |
|---|---|---|---|
| True positive (TP) | `#TP` | `c_tp` (often 0 or a small benefit) | Policy: value of catching a positive, net of handling cost. |
| False positive (FP) | `#FP` | `c_fp` | Review cost, customer-friction cost, or wrongful-action cost — cited to a written source. |
| False negative (FN) | `#FN` | `c_fn` | Expected downstream loss when a positive is missed, cited to a written source. |
| True negative (TN) | `#TN` | `c_tn` (usually 0) | No action; usually zero. |

Expected total cost on the eval set at threshold `t`:

```
E[cost | t] = c_tp · #TP(t) + c_fp · #FP(t) + c_fn · #FN(t) + c_tn · #TN(t)
```

A learner-grade worked cost model for a fraud-review classifier (illustrative, not a real number):

```yaml
# cost_model.yaml
version: "2026-11-13"
unit: "USD per decision"
assumptions:
  - "FP cost is one human review at ~$5 incl. fully loaded reviewer cost."
  - "FN cost is average chargeback + investigation at ~$180."
  - "TP cost is $5 (review happens either way); TN cost is $0."
  - "Volume = 1M decisions / week."
costs:
  c_tp: 5.00
  c_fp: 5.00
  c_fn: 180.00
  c_tn: 0.00
notes:
  - "FN cost is the single most sensitive input; a ±30% sensitivity sweep (see §2.5) is required."
  - "This cost model assumes reviewer capacity is not the binding constraint. If it becomes binding, re-derive under the capacity constraint (see §2.6)."
```

Rule: every number in `costs:` has a cited source — a finance ticket, an incident post-mortem, a pricing doc, or the policy that governs the decision. A cost model with no sources is a guess; a guess is still better than a hidden guess, but the sourcing is the control.

### 2.2 Score curve

Compute ROC and PR curves on the held-out eval set and *mark the candidate thresholds*. ROC is useful for argument; PR is often more useful for imbalanced problems because the baseline rate is visible. Report both.

A minimum report figure:

```
ROC                            PR
1 |          ●t*                1 |●t*
  |        ●                      | ●
  |      ●                        |   ●
  |    ●                          |     ●
  |  ●                            |        ●
0 ●─────────── 1              0 ● ─────────── 1
     FPR                            recall
```

Each marked threshold on the curve is an entry in a committed table: `(t, TP, FP, FN, TN, precision, recall, FPR, F1)`. The ROC/PR plot is for intuition; the table is for the decision.

### 2.3 Expected-cost sweep

Sweep `t` across a fine grid (or the set of unique scores) and compute `E[cost | t]`. Plot the curve. Mark the minimum; report its CI from a bootstrap on the eval set.

```
E[cost] 
  │  \                         ╱
  │   \                      ╱
  │    \                   ╱
  │      \               ╱
  │        \_         _╱
  │           \____╱
  │            t*
  └──────────────────────► threshold t
```

The minimum `t*` is the recommended operating point. Three secondary questions decide whether to actually ship `t*`:

1. **CI width.** Compute the CI of `E[cost | t*]` by bootstrapping the eval set. If `E[cost]` is flat near the minimum (wide CI, many `t` values within the CI of `t*`), the choice is not strongly determined by the data; prefer a threshold that is robust under the cost-sensitivity sweep in §2.5.
2. **Prevalence.** If the eval-set prevalence differs from production prevalence, re-weight before the sweep: `E[cost]` in production equals the eval-set `E[cost]` only when prevalence matches. This is where many learner solutions quietly go wrong.
3. **Capacity constraint.** If you have a fixed review budget (e.g. "reviewers can handle 15k items/week"), `t*` must additionally satisfy `FP(t) + TP(t) ≤ capacity`. The constrained minimum may not equal the unconstrained minimum.

### 2.4 Chosen operating point

The decision record:

```markdown
## Operating-point decision — 2026-11-13
- Model: `fraud-classifier@v7.4`
- Eval set: `eval-2026-w45` (hash `b17c…`)
- Cost model: `cost_model.yaml@v2026-11-13`
- Threshold: `t* = 0.317`
- Expected cost at t*: $0.082 per decision (95% CI $0.078–$0.086)
- Confusion at t* (held-out, n=74,312):
  - TP: 822   FP: 1,104   FN: 134   TN: 72,252
  - precision 0.427, recall 0.860, FPR 0.015
- Slice check: 0 of 12 slices regressed beyond the +15% cost floor at t*.
- Capacity check: predicted weekly review volume 1,926 items; cap 15,000 — within cap.
- Sensitivity: t* ∈ [0.28, 0.34] across ±30% c_fn and ±30% c_fp sweeps.
- Approver: @risk-lead, PR link: …
- Next review: next quarterly drift check, or any change to cost_model.yaml.
```

Per-slice verification: run §2.3 on every slice defined in exercise-01. If a slice's `E[cost | t*]` is more than a documented floor above its own minimum `E[cost | t*_slice]`, decide whether to ship a per-slice threshold (and inherit the fairness tradeoff from exercise-04) or to keep the global threshold and document the gap.

### 2.5 Sensitivity analysis

The most common failure of a cost-sensitive threshold is that it was chosen under a cost model nobody re-examined. The reference workflow sweeps:

- `c_fn` over `±30%` (the FN cost is almost always the dominant and most uncertain cell).
- `c_fp` over `±30%`.
- Prevalence over the range observed in the last four weeks.

Report a table of `t*` across the sweep. If `t*` moves by more than 0.05 across the sweep, the chosen threshold is cost-fragile; prefer a slightly higher-cost threshold that is stable across the sweep.

```
Sensitivity sweep of t* on fraud-classifier@v7.4

                       c_fn = $126 (-30%)   c_fn = $180 (base)   c_fn = $234 (+30%)
c_fp = $3.50 (-30%)     0.34                 0.30                 0.27
c_fp = $5.00 (base)     0.36                 0.317                0.29
c_fp = $6.50 (+30%)     0.38                 0.34                 0.31
```

Here `t*` moves across `[0.27, 0.38]` — about 0.11 wide. If the downstream consumer cannot tolerate that much movement, either the cost model needs tighter sourcing or the chosen `t` should be the midpoint of the sweep rather than the headline minimum.

### 2.6 Minimal reference implementation

```python
# operating_point.py
from dataclasses import dataclass
import numpy as np

@dataclass
class CostModel:
    c_tp: float
    c_fp: float
    c_fn: float
    c_tn: float

def expected_cost(threshold: float, scores: np.ndarray, y: np.ndarray, cm: CostModel) -> float:
    yhat = scores >= threshold
    tp = int(((yhat == 1) & (y == 1)).sum())
    fp = int(((yhat == 1) & (y == 0)).sum())
    fn = int(((yhat == 0) & (y == 1)).sum())
    tn = int(((yhat == 0) & (y == 0)).sum())
    total = cm.c_tp * tp + cm.c_fp * fp + cm.c_fn * fn + cm.c_tn * tn
    return total / len(y)

def sweep_thresholds(scores, y, cm, grid=None):
    grid = np.unique(scores) if grid is None else grid
    costs = np.array([expected_cost(t, scores, y, cm) for t in grid])
    i = int(costs.argmin())
    return {"t_star": float(grid[i]), "cost_star": float(costs[i]), "grid": grid, "costs": costs}

def bootstrap_t_star(scores, y, cm, n_boot=10_000, seed=0):
    rng = np.random.default_rng(seed)
    n = len(scores)
    ts = np.empty(n_boot)
    for i in range(n_boot):
        ix = rng.integers(0, n, n)
        r = sweep_thresholds(scores[ix], y[ix], cm)
        ts[i] = r["t_star"]
    lo, hi = np.quantile(ts, [0.025, 0.975])
    return float(lo), float(hi)

def constrained_sweep(scores, y, cm, capacity, prevalence_prod=None):
    # capacity = max number of positive predictions per batch
    # prevalence_prod lets you re-weight when eval-set prevalence != production
    ...
```

## 3. Validation steps

1. **Grid-density check.** Rerun the sweep on the full sorted set of unique scores, not on an arbitrary 0.01-step grid. Confirm `t*` lands on the same cell. A coarse grid can hide a sharper minimum.
2. **Prevalence-shift check.** Resample the eval set to a production-typical prevalence and re-sweep. If `t*` changes by more than 0.03, the shipped `t*` must be the prevalence-adjusted one.
3. **CI check.** The bootstrap CI for `t*` must fit inside the sensitivity sweep range. If the bootstrap CI is wider than the sensitivity sweep, the eval set is too small to pin a stable operating point.
4. **Capacity check.** Multiply weekly volume by `(FP(t*) + TP(t*)) / n` and compare to the review capacity. Ship only if within cap.
5. **Slice check.** Confirm no slice's `E[cost | t*]` is more than the committed floor above its own minimum. If a slice fails, the decision record must either ship a per-slice threshold or document the gap.
6. **Reversibility rehearsal.** Rollback to the previous `t_star` and rerun the eval; confirm the pipeline tolerates a threshold change without a deploy. If the threshold is baked into the model binary, that is a bug the operating-point exercise should catch.
7. **Adversarial drift ping.** Simulate a score-distribution shift (shift all scores by +0.05). Confirm `E[cost]` degrades measurably and the monitor fires. This is the ML09 / ATLAS detection check.

## 4. Rubric

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Cost matrix is committed with cited sources | 2 | Each of `c_tp`, `c_fp`, `c_fn`, `c_tn` has a cited source; the unit and volume are named. |
| R2 | Expected-cost sweep is computed, not a Youden/F1 shortcut | 2 | `E[cost \| t]` curve is in the report; the minimum is named and justified against the cost model. |
| R3 | 95% CI for t* and E[cost \| t*] is reported | 1 | Bootstrap seed and resample count are committed; CIs appear in the decision record. |
| R4 | Sensitivity sweep over ±30% on the dominant cost and over prevalence | 2 | Table of `t*` across the sweep is in the report; if `t*` is fragile, the chosen `t` is defended. |
| R5 | Per-slice operating-point verification | 1 | No slice regresses beyond the committed floor at the global `t*`, or a per-slice decision is documented. |
| R6 | Capacity constraint is honored | 1 | Predicted positive-prediction volume at `t*` is below any named capacity cap, or the constrained optimum is shipped instead. |
| R7 | Decision record names approver and next-review trigger | 1 | Threshold change requires a new PR with a new cost model or eval; "shipped by consensus" is not acceptable. |

**Passing bar:** 7 / 10.

### Review checklist (for a maintainer)

- [ ] Every number in the cost model has a cited source (ticket, doc, incident).
- [ ] The minimum of `E[cost | t]` is on the plot, with a CI.
- [ ] Prevalence in the eval set matches the production prevalence — or the sweep is prevalence-adjusted.
- [ ] A capacity check is in the record if a review queue exists.
- [ ] Sensitivity sweep is present; a fragile `t*` is called out.
- [ ] A rollback plan exists and has been rehearsed at least once.

## 5. Common mistakes

- **Picking `t` from F1 or Youden's J.** F1 and Youden's J implicitly assume equal costs. If the costs are unequal, the threshold they produce is only correct by coincidence.
- **Cost model with no citations.** "FP costs ~$5" with no source is a guess; a sensitivity sweep around that guess is the cheapest way to turn it into a defensible decision.
- **Mismatched prevalence.** Eval set is class-balanced for training convenience; production is 1%. The threshold that minimizes cost on the eval set does not minimize cost in production. Re-weight before the sweep.
- **Grid too coarse.** A 0.01-step sweep can skip a sharper minimum that an `np.unique(scores)` sweep finds.
- **Ignoring the per-slice check.** The global `t*` can look good while silently costing a minority slice more than it costs the majority. See exercise-04.
- **Ignoring capacity.** `t*` without a capacity check can prescribe more review volume than the humans can absorb; in practice this produces de facto `t` drift as the queue overflows.
- **Threshold baked into the model.** If the shipped artifact has `>= 0.5` compiled in, every threshold change is a model deploy. Keep `t` separate and versioned.
- **No monitoring.** `t*` is a snapshot; without a monitor, drift re-introduces the asymmetric cost the exercise was supposed to control.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function asks for metrics tied to the context of use; `MANAGE` governs the change control around a chosen operating point. A cost-asymmetric threshold is measured once but *managed* continuously.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML09 Output Integrity Attack is the adversarial motivation for monitoring the operating point: an attacker who shifts the score distribution causes exactly the cost asymmetry the chosen threshold was tuned against.
- MITRE ATLAS — <https://atlas.mitre.org/>. The `Evade ML Model` and `Verify Attack` tactics describe adversaries probing decision boundaries; drift of `E[cost | t*]` is the defender's detection signal for those tactics.

<!-- Local exercise context: the fraud-classifier worked numbers (c_fn = $180, capacity = 15k reviews/week, ±30% sweep) are illustrative. Real cost cells and sensitivity ranges must be sourced to the actual deployment's financial and operational data. -->
