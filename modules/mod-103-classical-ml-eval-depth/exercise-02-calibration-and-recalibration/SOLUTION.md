# exercise-02 — Calibration and Recalibration — Solution

## 1. Solution overview

The exercise asks the learner to **measure calibration**, **choose a recalibration method**, and **decide when recalibration is justified** for a probabilistic classifier whose downstream consumer uses the predicted probability (not just the argmax) to make a decision — thresholding, expected-cost routing, downstream aggregation, or human review prioritization.

The reference answer has four pieces:

1. A **measurement protocol** — which calibration diagnostics the learner computes, how they are binned, and the uncertainty around each.
2. A **recalibration decision tree** — the conditions that select Platt scaling, isotonic regression, or temperature scaling, and the conditions under which recalibration is *not* appropriate.
3. A **fit / validate / monitor loop** — recalibrator fit on held-out data, validated on a disjoint split, monitored per slice over time.
4. A **governance wrapper** — versioning, rollback, and the written rule for when a recalibrated model displaces the previous one.

This maps directly to the NIST AI RMF `MEASURE` function, which calls for "metrics that are accurate, reliable, and relevant" — a model that scores well on accuracy but mis-reports probabilities is neither reliable nor relevant for a downstream consumer that uses the probability ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). Calibration drift is the measurement side of OWASP ML Top 10 **ML09 Output Integrity Attack** — a corrupted or drifting scoring pathway reports probabilities that no longer mean what the consumer thinks they mean ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS's `Craft Adversarial Data` and `ML Model Poisoning` entries describe adversaries deliberately pushing a model's probabilities away from reality; calibration monitoring is the detection evidence ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Implementation

### 2.1 Measurement protocol

Calibration is "does the predicted probability equal the empirical rate?" Three diagnostics, computed together:

**D1 Reliability diagram.** Bin the predicted probabilities and, within each bin, plot mean predicted probability (x-axis) against observed positive rate (y-axis). A perfectly calibrated model lies on the diagonal. Both equal-width bins (10 bins over [0,1]) and equal-count bins are acceptable — report which you used. Equal-count bins remove the "empty bin" artifact at the tails.

**D2 Expected Calibration Error (ECE).** The weighted average, over bins, of `|accuracy - confidence|`. One scalar that compresses the diagram. Known caveats: ECE is sensitive to the binning scheme, it does not capture sign (over- vs under-confident), and it hides per-slice effects. Always report alongside the diagram and alongside per-slice ECE.

**D3 Brier score.** Mean squared error between predicted probability and the binary outcome. A *proper* scoring rule — a model cannot game it by hedging toward 0.5. Brier can be decomposed into reliability, resolution, and uncertainty; report the reliability component when you have the compute budget, since it is the calibration-specific piece.

Confidence intervals: a bootstrap of 10,000 resamples on the eval set gives a 95% CI around ECE and Brier. Without a CI, a 0.01 drop is indistinguishable from noise.

Minimum table in the report:

```
model        n      ECE (10 eq-count bins)   Brier   Brier-reliability   ACC@0.5
baseline    74312   0.034 (0.030, 0.038)     0.081   0.0029              0.86
candidate   74312   0.012 (0.010, 0.014)     0.079   0.0004              0.86
```

And a reliability diagram for the aggregate plus **one diagram per slice** on the dashboard (see exercise-01). Calibration gaps very often live in a slice while the aggregate looks fine.

### 2.2 Recalibration decision tree

Pick *one* recalibrator, from a short list, by matching the data and model shape to its assumptions.

```
                                   Is the model a deep NN with a
                                   logit layer and a held-out set?
                                            │
                              yes ──────────┤────────── no
                               │                         │
                 ▼ Temperature scaling              Do you have                 
                 (single-parameter T on logits;      ≥ 1k held-out              
                 cheapest, preserves ranking)        labels?                   
                                                        │                     
                                               yes ─────┤───── no              
                                                │              │               
                                   Is the miscalibration     Report: insufficient
                                   roughly sigmoidal         data to recalibrate; 
                                   (one over/under-conf      ship model as-is or    
                                   bulge)?                   collect more labels.
                                            │                                   
                               yes ─────────┤─────────── no                    
                                │                        │                     
                      ▼ Platt scaling             ▼ Isotonic regression       
                      (2 parameters)              (nonparametric, needs       
                                                   several hundred labels per  
                                                   bend, monotonic by design)  
```

Guidance per method:

- **Temperature scaling.** Fit a single scalar `T` on the held-out logits by minimizing NLL. Preserves argmax, trivially monotonic, cheapest, and the de facto default for deep nets. Fails when the miscalibration is not uniform across the logit range.
- **Platt scaling.** Logistic regression with two parameters `(A, B)` on the raw scores. Fine for small held-out sets; biased when the true miscalibration curve is not sigmoidal.
- **Isotonic regression.** Nonparametric, monotonic, strictly more expressive than Platt. Needs more data (empirically, several hundred positives *and* negatives), and can overfit if the held-out set is small or bin-sparse. Preserves ranking.
- **Beta calibration / spline calibration.** Acceptable extensions when the sigmoid shape is wrong and isotonic is overfitting. Not required for the exercise but worth naming in the rationale section.

**When recalibration is not appropriate.** The decision tree must have refusal leaves:

- The distribution shift between training and deployment violates the `calibration ≈ identity under a shifted score distribution` assumption. Monitor and retrain, do not slap a recalibrator on top.
- Labels are unreliable (e.g., silver labels or weak supervision). Recalibrator fit on noisy labels inherits the noise.
- The held-out set is under 1,000 items, or has fewer than ~50 positives. Recalibrators overfit on small samples; the "fix" will be worse than the original miscalibration.
- Per-slice calibration gaps are moving in opposite directions. A single global recalibrator will make some slices worse (see §2.4).

### 2.3 Fit / validate / monitor loop

Three disjoint splits — **never** fit a recalibrator on the test split that reports ECE.

```
train (model)   ──►  held-out A (recalibrator fit)   ──►  held-out B (recalibrator validate)   ──►  test (headline ECE)
```

The headline ECE and Brier in the ship report come from the test split, which the recalibrator has never seen. Learner implementations commonly collapse A and B into a single split — this is acceptable only if cross-validation is used to fit the recalibrator, with the CV protocol written down.

Minimum artifacts committed:

- `recalibrators/<model_version>/<method>.pkl` — the fitted recalibrator, with a sidecar `metadata.yaml` recording method, hyperparameters, split hashes, label version, and git SHA.
- `recalibrators/<model_version>/eval.md` — the reliability diagrams and metrics on held-out B, plus the per-slice table.
- `recalibrators/<model_version>/CHANGELOG.md` — one line per version with the Δ metric.

**Monitoring.** After ship, re-measure ECE on each slice at every eval run and gate on it (the CAL gate from exercise-01). A rising per-slice ECE at steady accuracy is the exact signal ML09 and ATLAS "Craft Adversarial Data" leave: the model still gets the argmax right, but the probability is no longer trustworthy.

### 2.4 Per-slice calibration

A global recalibrator can *reduce* average ECE while *increasing* per-slice ECE on a minority slice. The reference workflow requires:

1. Compute pre- and post-recalibration ECE on every slice that appears in the dashboard.
2. Reject a recalibrator whose per-slice ECE regresses on any slice beyond a documented floor (e.g. `+0.01` absolute). Overall improvement is not an excuse.
3. If (2) rejects every candidate, consider a **group-conditional** recalibrator (one recalibrator per slice or per grouping), with explicit discussion of the fairness trade-offs raised in exercise-04.

### 2.5 Minimal reference implementation

```python
# calibration.py
from dataclasses import dataclass
from typing import Literal, Protocol
import numpy as np

Method = Literal["temperature", "platt", "isotonic"]

@dataclass
class EvalReport:
    ece: float
    ece_ci: tuple[float, float]
    brier: float
    brier_reliability: float
    diagram_png_path: str
    n: int
    seed: int
    bins_strategy: str  # "equal_width" | "equal_count"
    n_bins: int

class Recalibrator(Protocol):
    def fit(self, scores: np.ndarray, y: np.ndarray) -> "Recalibrator": ...
    def transform(self, scores: np.ndarray) -> np.ndarray: ...

def ece(p: np.ndarray, y: np.ndarray, bins: int = 10, strategy: str = "equal_count") -> float:
    if strategy == "equal_count":
        quantiles = np.quantile(p, np.linspace(0, 1, bins + 1))
        quantiles[0], quantiles[-1] = 0.0, 1.0 + 1e-12
        idx = np.digitize(p, quantiles) - 1
    else:
        idx = np.minimum((p * bins).astype(int), bins - 1)
    total = 0.0
    n = len(p)
    for b in range(bins):
        mask = idx == b
        if not mask.any():
            continue
        conf = p[mask].mean()
        acc = y[mask].mean()
        total += (mask.sum() / n) * abs(acc - conf)
    return float(total)

def brier(p: np.ndarray, y: np.ndarray) -> float:
    return float(((p - y) ** 2).mean())

def bootstrap_ci(fn, p, y, n_boot=10_000, seed=0, alpha=0.05) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    n = len(p)
    out = np.empty(n_boot)
    for i in range(n_boot):
        ix = rng.integers(0, n, n)
        out[i] = fn(p[ix], y[ix])
    lo, hi = np.quantile(out, [alpha / 2, 1 - alpha / 2])
    return float(lo), float(hi)
```

Recalibrator implementations (temperature / Platt / isotonic) are standard and omitted here — `sklearn.isotonic.IsotonicRegression`, `sklearn.linear_model.LogisticRegression` on scores for Platt, and a one-parameter optimizer on NLL for temperature are sufficient. What matters for the exercise is the **pipeline around them**, not the recalibrator math.

## 3. Validation steps

1. **Split disjointness.** Assert that the hashes of the test-split items are disjoint from the recalibrator-fit split. If they overlap, the headline ECE is meaningless.
2. **Monotonicity preservation.** Temperature and isotonic preserve argmax by construction; Platt preserves it for binary classification. Confirm that the top-1 accuracy before and after recalibration are identical on the test split (within ±one item — floating-point ties).
3. **Reliability diagram sanity.** Before recalibration, the diagram should be visibly off-diagonal; after, it should be on-diagonal within CI. If both look on-diagonal, your model may already be calibrated and you are solving the wrong problem.
4. **Per-slice non-regression.** Run the slice dashboard twice (pre- and post-recalibration) and confirm no slice regressed beyond the documented floor. If one did, section §2.4 applies.
5. **Small-sample refusal.** Attempt to fit isotonic on 200 items; the pipeline must either refuse or emit a prominent warning. Isotonic with 200 items overfits.
6. **Drift replay.** Take last quarter's eval set and re-score with today's model + recalibrator. If ECE has drifted upward beyond the ceiling, the CAL gate must trip. If it does not, the monitor is cosmetic.
7. **Adversarial drift.** Shift the input distribution on a controlled slice by 10% (e.g. perturb an upstream feature). Confirm that aggregate ECE moves measurably; this is the ML09 / ATLAS detection check.

## 4. Rubric

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | ECE, Brier, and a reliability diagram are all reported | 2 | All three appear in the report, with the binning strategy and bin count labeled. |
| R2 | 95% CIs are reported for ECE and Brier | 1 | Bootstrap seed and resample count are committed; CIs appear in the table. |
| R3 | Splits are disjoint and labeled | 1 | Three splits (model train / recalibrator fit / recalibrator validate) are named, with the test split reserved for headline ECE. |
| R4 | Recalibration method selected with written rationale | 2 | Decision tree in §2.2 is referenced; the choice names the method's assumption and shows it holds on the data. |
| R5 | Per-slice ECE is computed and gate-protected | 2 | No slice regresses beyond the committed floor; a group-conditional recalibrator or a decline-to-recalibrate decision is documented if a slice would regress. |
| R6 | Recalibrator is versioned and rollback-ready | 1 | Fitted artifact + metadata + CHANGELOG committed; previous version still loadable. |
| R7 | Monitoring plan with a CAL gate is written down | 1 | Dashboard CAL gate references the per-slice ECE ceiling; drift triggers a ticket, not silence. |

**Passing bar:** 7 / 10.

### Review checklist (for a maintainer)

- [ ] Reliability diagram axes are labeled and the binning strategy is named in the caption.
- [ ] The recalibrator is fit on a split the test set has never seen.
- [ ] Per-slice ECE table is in the report, not only the aggregate.
- [ ] The decision to **not** recalibrate is as well-documented as a decision to recalibrate.
- [ ] A CAL gate exists on the dashboard and has a defined response policy.

## 5. Common mistakes

- **Reporting ECE with no diagram.** ECE is a one-number compression; it hides direction (over- vs under-confidence) and shape (one bulge vs multiple).
- **Fitting the recalibrator on the test split.** This is the most common critical error. The headline ECE becomes fiction.
- **Equal-width binning on a skewed score distribution.** Most bins are empty, a few are packed; ECE looks artificially low. Report equal-count bins alongside.
- **Ignoring slice-level calibration.** A global recalibrator can lower aggregate ECE while raising minority-slice ECE. The fairness exercise (04) picks this up again.
- **Isotonic on a tiny validation set.** Isotonic needs the data to find the shape; under ~several hundred positives and negatives it overfits dramatically.
- **Not versioning the recalibrator.** The recalibrator is a model; it drifts, it rolls back, it needs a changelog like any other model.
- **Treating recalibration as a substitute for retraining under drift.** If the score distribution has moved because the world moved, a recalibrator slapped on top is a band-aid; the correct action is often to retrain.
- **No monitoring.** A one-shot calibration measurement is a snapshot; without a CAL gate the next ECE regression ships silently.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function sets the bar for probability outputs to be accurate and reliable, which is the formal reason to measure and maintain calibration, not only accuracy.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML09 Output Integrity Attack describes adversaries corrupting the scoring pathway; calibration drift is the detection signal.
- MITRE ATLAS — <https://atlas.mitre.org/>. The `Craft Adversarial Data` and `ML Model Poisoning` entries describe adversaries pushing probabilities away from truth without necessarily moving argmax accuracy; calibration monitoring is the defender's evidence trail.

<!-- Local exercise context: specific thresholds in the decision tree (held-out size of 1,000, floor of +0.01 absolute slice ECE regression, 10 equal-count bins) are defensible defaults and must be re-chosen per deployment based on label budget, prevalence, and consumer sensitivity to probability error. -->
