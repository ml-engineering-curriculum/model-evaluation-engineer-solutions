# exercise-04 — Sequential Testing and Confidence Sequences for Continuous Monitoring — Solution

## 1. Solution overview

Classical fixed-horizon A/B testing has a single analysis point: you declare a sample size up front, you wait, you test once. The moment you peek at interim results and re-apply a 0.05 threshold at each peek, the false-positive rate inflates — a run that would be declared "significant" under a single-look design is now a run that will be declared significant *eventually* under any random walk. The practical problem is that production teams always peek. A model under continuous monitoring produces a stream of outcomes forever; declaring one horizon and waiting is not an option.

**Sequential tests** and **confidence sequences** are the tools that let you peek legitimately. They produce an "always-valid" error bound: you can look at the running statistic as often as you want and the family-wise type-I error over all looks is still at most `α`. Three families are in production use:

- **Group sequential tests** (O'Brien–Fleming, Pocock boundaries): plan `K` interim looks; spend `α` across them under a monotone boundary. Published designs; closed-form boundaries.
- **mSPRT / always-valid p-values** (Johari, Pekelis, Walsh 2017 / Johari, Koomen, Pekelis, Walsh 2021): compute a sequential probability ratio at each observation; a running `p_t` that is a valid p-value at every `t`.
- **Confidence sequences** (Howard, Ramdas, McAuliffe, Sekhon 2021, "Time-uniform, nonparametric, nonasymptotic confidence sequences"): CIs `(L_t, U_t)` that cover the true parameter with probability `≥ 1 - α` **simultaneously** across all `t`. The ship-or-stop decision becomes "does the confidence sequence exclude zero" — the shape every engineer actually wants.

The reference solution builds a **confidence-sequence monitor** on the running paired-difference metric from the shadow / experiment, with two ancillary paths: a classical group-sequential design for pre-planned analyses with discrete interim looks, and an always-valid p-value readout for teams who want a single number at each peek. Stopping is a committed policy — early stop for efficacy, early stop for futility, hard stop at a maximum sample — and each path writes an audit trail.

The reference answer has five deliverables:

1. A **monitor design** — the metric, the unit, the paired/unpaired structure, the committed `α`, the futility threshold, and the maximum sample `N_max`.
2. A **confidence-sequence implementation** (`cs.py`) that updates `(L_t, U_t)` incrementally and exposes a `stop?` query at each timestep.
3. A **group-sequential alternative** (`gs.py`) for pre-planned `K` looks with O'Brien–Fleming boundaries.
4. A **stopping-policy evaluator** — `stop_for_efficacy`, `stop_for_futility`, `stop_for_cap` — that runs at every peek and emits a `decision.jsonl` row (an ever-growing audit log).
5. A **monitoring report** — plot of running `(L_t, U_t)`, decisions, and per-peek timestamps; manifest pins the `α` schedule, futility threshold, and `N_max`.

This maps to the NIST AI RMF `MEASURE` and `MANAGE` functions ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)) — a monitor with time-uniform error control is a tested, documented method with explicit stopping rules. The adversarial lens is OWASP ML Top 10 **ML09 Output Integrity Attacks**: naive repeated peeking at fixed-horizon p-values will ship regressions and roll back improvements at a false rate well above the nominal `α` — the eval has been attacked by its own dashboard ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0015 Evade ML Model` describes the inverse case where the adversary times inputs to exploit an under-monitored tail; a confidence sequence with an `N_max` and a committed stop-for-cap rule bounds the window in which such an attack can run unnoticed ([MITRE ATLAS](https://atlas.mitre.org/)).

The confidence-sequence construction below uses the sub-Gaussian / Hoeffding-type bound; for bounded binary outcomes the empirical Bernstein variant is tighter and the reference below is to the Howard et al. paper for the general method.

## 2. Worked implementation

### 2.1 Monitor shape

The monitor runs on a stream of per-unit outcomes `(unit_id, exposure_ts, Y_i, X_i, arm)` and maintains running statistics. Every `peek_interval` (a scheduled timer, e.g., every hour), the monitor reads the current statistics, calls the sequential test, writes a `decision` row, and takes an action if the stop rule fires.

```
+------------+   peek timer    +-----------------+   decision      +-----------+
|  outcomes  | --------------->|  seq_monitor.py |---------------->| decisions |
|  stream    |                 |  (CS / GS / AV) |    .jsonl       |  audit    |
+------------+                 +-----------------+                 +-----------+
                                        |
                                        v
                                +--------------+
                                | action.py    |  (page, halt, ramp)
                                +--------------+
```

Committed defaults:

- **Metric:** paired-diff `D_i = Y_i^{t} - Y_i^{c}` (if paired, e.g., a shadow comparison) or an unpaired mean-difference ATE (if a between-arm A/B).
- **α = 0.05 (two-sided)**, time-uniform. "0.05 at every look" means **family-wise across all looks**, not per look.
- **Futility threshold:** stop early for futility when the CS upper bound (favorable direction) is below a committed minimum interesting effect `MIE`.
- **`N_max`:** hard sample ceiling at which the test stops regardless of boundary — forces a decision instead of running forever.

### 2.2 Confidence sequence (`cs.py`)

A sub-Gaussian confidence sequence for the sample mean (Howard, Ramdas, McAuliffe, Sekhon 2021). Bounds `|μ_hat_t − μ| ≤ r(t)` time-uniformly with probability `≥ 1 - α`:

```
r(t) = σ * sqrt( (2 * (t * ρ^2 + 1) / (t^2 * ρ^2)) * log( sqrt(t * ρ^2 + 1) / α ) )
```

with free tuning parameter `ρ > 0` chosen at design time (not shopped during the run).

```python
"""Time-uniform confidence sequence for a running mean on bounded data.

The sub-Gaussian variant uses an upper bound on sigma; for 0/1 outcomes the
natural sigma is 1/2. For continuous outcomes, pin sigma to a conservative
pre-period estimate (never estimated during the run, which would make the
guarantee heuristic)."""

from __future__ import annotations
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class CSParams:
    alpha: float
    sigma: float       # conservative upper bound on std; committed up front
    rho: float         # tuning parameter; typical 1/sqrt(t0) for a target t0


@dataclass
class ConfidenceSequence:
    params: CSParams
    _n: int = 0
    _sum: float = 0.0
    _sum_sq: float = 0.0

    def update(self, x: float) -> None:
        self._n += 1
        self._sum += x
        self._sum_sq += x * x

    @property
    def mean(self) -> float:
        return self._sum / self._n if self._n else 0.0

    def radius(self) -> float:
        n = self._n
        if n == 0:
            return math.inf
        p = self.params
        inner = (n * p.rho**2 + 1) / (n**2 * p.rho**2)
        log_term = math.log(math.sqrt(n * p.rho**2 + 1) / p.alpha)
        return p.sigma * math.sqrt(2 * inner * log_term)

    def interval(self) -> tuple[float, float]:
        r = self.radius()
        return (self.mean - r, self.mean + r)

    def excludes(self, value: float) -> bool:
        lo, hi = self.interval()
        return value < lo or value > hi
```

Design rules worth calling out:

- **`σ` is committed up front**, from pre-period data. Estimating `σ` during the run and reusing it in the bound breaks the time-uniform guarantee; a plug-in `σ` is a heuristic, not a bound.
- **`ρ` is fixed at design time.** `ρ` controls where the CS is tightest. Choose `ρ ≈ 1/√t_target` for the target sample size `t_target` at which you expect to decide; a dynamic `ρ` invalidates the proof.
- **The CS is one-sided or two-sided deliberately.** A primary-metric CS that is two-sided detects regressions and improvements with equal error budget; a "ship if excludes zero from above" question is a one-sided CS with full `α` in that direction. Pin the choice in the manifest.
- **Report `mean`, `(L_t, U_t)`, and `t`.** A bare "excludes zero" decision without the three underlying quantities is not an audit trail.
- **Do not reset `n`.** The CS is monotone in the proof; a mid-run reset of counters invalidates time-uniform coverage.

### 2.3 Group-sequential alternative (`gs.py`)

For teams who need discrete interim looks with pre-planned boundaries:

```python
"""O'Brien-Fleming group-sequential test with K pre-planned looks.

At look k (out of K), the z-statistic is compared to the boundary
z_k = c / sqrt(k/K) where c is chosen so the maximum rejection prob
across k=1..K under the null is <= alpha. For a two-sided test, use
scipy to solve for c numerically (or import the standard table).
"""

from __future__ import annotations
import math
from scipy.stats import norm


def obrien_fleming_boundaries(alpha: float, K: int) -> list[float]:
    """Return z_1..z_K such that P(reject | H0) <= alpha across the K looks."""
    from scipy.optimize import brentq

    def total_alpha(c: float) -> float:
        # Approximate by independent-boundary tail probabilities; close
        # enough for K<=10 and small alpha; use lan-demets alpha-spending
        # for tighter calibration in production.
        boundaries = [c / math.sqrt(k / K) for k in range(1, K + 1)]
        return sum(2 * (1 - norm.cdf(b)) for b in boundaries) - alpha

    c = brentq(total_alpha, 0.5, 10.0)
    return [c / math.sqrt(k / K) for k in range(1, K + 1)]


def gs_decide(z_k: float, boundary: float) -> str:
    if abs(z_k) >= boundary:
        return "stop_efficacy"
    return "continue"
```

Rules:

- **`K` is pre-declared.** Adding a look post-hoc is not a boundary, it is a free peek.
- **Lan–DeMets α-spending** is the correct generalization for uneven information fractions (the real timing of looks) and is the recommended production design; the inline approximation here is for teaching.
- **O'Brien–Fleming is conservative early**, allowing most of the type-I budget to be spent at the final look. Pocock boundaries are flat; choose at design time based on how important early stopping is.

### 2.4 Stopping policy (`policy.py`)

```python
"""Composite stop evaluator: efficacy, futility, cap. Writes one row per peek."""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class StopPolicy:
    mie: float          # minimum interesting effect; futility if U_t < mie
    n_max: int          # hard cap; stop when t >= n_max
    direction: str      # "higher_is_better" | "lower_is_better"


def decide(cs, policy: StopPolicy, t: int) -> dict:
    lo, hi = cs.interval()
    ans = "continue"
    reason = None
    if policy.direction == "higher_is_better":
        if lo > 0:
            ans, reason = "stop_efficacy", f"L_t={lo:.4f}>0"
        elif hi < policy.mie:
            ans, reason = "stop_futility", f"U_t={hi:.4f}<MIE={policy.mie}"
    else:
        if hi < 0:
            ans, reason = "stop_efficacy", f"U_t={hi:.4f}<0"
        elif lo > -policy.mie:
            ans, reason = "stop_futility", f"L_t={lo:.4f}>-MIE"
    if ans == "continue" and t >= policy.n_max:
        ans, reason = "stop_cap", f"t={t}>=N_max={policy.n_max}"
    return {
        "t": t,
        "mean": cs.mean,
        "ci_lo": lo,
        "ci_hi": hi,
        "decision": ans,
        "reason": reason,
    }
```

Three rules the policy enforces:

- **Efficacy > futility > cap.** If both efficacy and cap trigger on the same peek, the decision is `stop_efficacy`. Cap is a floor, not a veto on the signal.
- **`MIE` is committed at design time.** A futility threshold chosen after the data is collected is a free pass to stop whenever the owner wants.
- **`stop_cap` is a decision, not a no-decision.** Running forever and reporting "inconclusive" is not an audit outcome. The report names the cap, the observed CI, and the owner.

### 2.5 Peek audit log

Every peek writes one line to `decisions.jsonl`:

```json
{
  "run_id": "monitor_quality_llm_v7_2026-11",
  "peek_ts": "2026-11-20T14:05:00Z",
  "t": 184_312,
  "mean": 0.041,
  "ci_lo": 0.034,
  "ci_hi": 0.048,
  "mie": 0.010,
  "direction": "higher_is_better",
  "decision": "stop_efficacy",
  "reason": "L_t=0.034>0",
  "cs_params": {"alpha": 0.05, "sigma": 0.25, "rho": 0.003},
  "monitor_commit": "<git sha>"
}
```

Rules:

- **Append-only.** A monitor that rewrites past peeks is not an audit log; it is a diary.
- **Timestamp at the server.** Peek clocks must be the monitor's clock, not the dashboard's — otherwise retroactive timezone changes re-order decisions.
- **One line per peek**, even for `continue`. A missing "continue" row would make a later "stop" row appear to come out of nowhere.

### 2.6 Monitoring report and manifest

`monitor_report_<run_id>.md` opens with the running plot and the first `stop` row:

```markdown
# Continuous monitor monitor_quality_llm_v7_2026-11 — 2026-11-01 to 2026-11-20

**First stop event:** 2026-11-20T14:05Z — stop_efficacy (L_t=0.034 > 0)

## Running CI
| peek_ts | t | mean | 95% CS | decision |
|---|---|---|---|---|
| 2026-11-08T02:00Z | 12_014 | 0.018 | [-0.009, +0.045] | continue |
| 2026-11-12T02:00Z | 48_207 | 0.028 | [+0.005, +0.051] | continue |
| 2026-11-15T02:00Z | 92_188 | 0.034 | [+0.016, +0.052] | continue |
| 2026-11-20T14:05Z | 184_312 | 0.041 | [+0.034, +0.048] | stop_efficacy |
```

Manifest `monitor_run.yaml`:

```yaml
run_id: monitor_quality_llm_v7_2026-11
metric:
  name: paired_quality_delta
  unit: user_id
  direction: higher_is_better
sequential_test:
  family: confidence_sequence
  variant: sub_gaussian
  alpha: 0.05
  sigma: 0.25            # pre-period upper bound; committed
  rho: 0.003             # chosen for t_target=100000
stopping_policy:
  mie: 0.010
  n_max: 1_000_000
peek_interval_s: 3600
window:
  start: 2026-11-01T00:00:00Z
  end:   null             # open-ended until stop or cap
alternatives_tried:
  - "obrien_fleming: K=5 looks, not used (chose CS for flexibility)"
seed: 20261120
monitor_commit: <git sha>
```

## 3. Validation steps

1. **Time-uniform calibration simulation.** Run `N = 10_000` replications of the null (both arms draw from the same distribution). The fraction of replications that *ever* trigger `stop_efficacy` at any peek is ≤ `α` (within Monte-Carlo noise). If the fraction exceeds `α`, the CS is mis-constructed or `σ` was underestimated.
2. **Monotone CI radius-shrinkage.** For any run, `r(t)` is non-increasing in `t` once `t ≥ some constant`. A run where the CI *widens* with more data is a bug in the recurrence (double-increment of `_n`, reset of `_sum`, etc.).
3. **Deterministic `rho` and `sigma`.** Rerun of the monitor over the same event stream produces identical `(L_t, U_t)` at every peek. CI pass requires this.
4. **Append-only audit log.** CI runs `git diff` on `decisions.jsonl` across two runs and fails if any line was rewritten.
5. **Policy-order test.** On a synthetic series where efficacy and cap trigger on the same peek, the decision is `stop_efficacy`.
6. **Stop-cap-is-a-decision test.** A synthetic series that never crosses the boundary runs to `t = N_max` and emits `stop_cap`; the next peek does not add another row (the monitor is stopped).
7. **One-sided vs two-sided wiring.** For a one-sided monitor, `interval()` returns `(L_t, +∞)` or `(-∞, U_t)`; a two-sided monitor returns a two-sided CI. The manifest declares which.
8. **Peek-interval respected.** The scheduler does not add bonus peeks outside the committed cadence; a test with a mocked clock asserts exactly N peeks across a window of N × interval.
9. **Monte-Carlo bootstrap of the CS width.** Compare the empirical 1-α coverage to the theoretical bound over many simulated streams; `coverage ≥ 1 - α - ε` for small `ε`.
10. **Comparison to fixed-horizon.** On a synthetic AA-test (both arms identical), the monitor's false-positive rate across many runs is substantially below what a naive repeated 0.05 fixed-horizon z-test would produce; the committed sim is the evidence the method works.

## 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Monitor uses an always-valid method (CS, mSPRT, or group-sequential with pre-planned looks and spending function) | 2 | `cs.py` or `gs.py` with committed parameters; naive repeated z-tests are not permitted. |
| R2 | `σ`, `ρ`, `α` committed at design time | 1 | Manifest pins all three; no in-run estimation of `σ` used in the bound. |
| R3 | Simulated null-coverage test passes | 2 | `tests/test_cs_null.py`: 10k replications, empirical false-positive ≤ α. |
| R4 | Stop policy includes efficacy, futility (vs MIE), and cap | 1 | `policy.py` returns one of the three; synthetic tests pin each path. |
| R5 | Append-only peek audit log with one row per peek | 1 | `decisions.jsonl` is append-only; `continue` rows present; timestamps monotone. |
| R6 | Report surfaces first stop event and running CI table | 1 | `monitor_report_*.md` layout. |
| R7 | One-sided / two-sided wiring is explicit and tested | 1 | Manifest declares; test covers both. |
| R8 | Manifest pins metric, unit, α, σ, ρ, MIE, N_max, peek interval, seed | 1 | `monitor_run.yaml` has every field. |

**Passing bar:** 7 / 10. R1 and R3 are non-negotiable — a monitor without time-uniform error control is a false-positive factory; the simulation is the evidence the implementation actually controls the error.

Reviewer checklist:

- [ ] Monitor uses CS / mSPRT / pre-planned group-sequential, not repeated fixed-horizon z-tests.
- [ ] `α`, `σ`, `ρ` committed in manifest; `σ` from pre-period, not in-run.
- [ ] Simulated null coverage passes (`sim_null.py` committed; empirical ≤ α).
- [ ] Stop policy returns `stop_efficacy`, `stop_futility`, `stop_cap`, or `continue`; synthetic tests exercise each.
- [ ] Peek log append-only; every peek has a row, including `continue`.
- [ ] Report names first stop event, decision, reason, and running CI table.
- [ ] One-sided vs two-sided wiring is explicit and tested.
- [ ] Manifest has the full parameter list.

## 5. Common mistakes

- **Fixed-horizon z-test at every peek.** Daily 0.05 tests on a running AA stream will trigger "significance" at a rate well above 0.05 within a couple of weeks. Use an always-valid method.
- **Re-estimating `σ` from the run and plugging it into the bound.** The time-uniform guarantee is for a *fixed* `σ`. A data-driven plug-in is a heuristic; the coverage proof no longer applies.
- **Choosing `ρ` after seeing the data.** `ρ` controls the sweet spot of the CI; shopping it for significance is equivalent to shopping `α`.
- **No `N_max`.** A monitor without a cap runs indefinitely and can never return "inconclusive at N_max"; the stop reason is forever `continue`.
- **Missing `MIE`.** Without a minimum interesting effect, futility never fires and the monitor chases uninteresting signals for months. Commit `MIE`.
- **Running monitor on the same data as the design.** Choosing `σ` from the same stream the monitor is running on is a chicken-and-egg; the design uses a pre-period or a committed historical bound.
- **Rewriting past decisions.** A monitor whose past rows can be edited is not an audit log. Append-only.
- **Peek-log entries only on decisions.** A missing `continue` log makes it impossible to know whether the monitor was running. Log every peek.
- **Conflating pair-level and user-level variance.** If the stream is paired-by-user, the variance is per-user. Feeding per-pair observations into a mean-of-paired-differences without the user-level grouping underestimates `σ` and over-tights the CI.
- **Switching family mid-run.** Starting with group-sequential and switching to a CS half-way through is two tests under one `α`. Commit the family.
- **Treating `stop_cap` as "nothing happened."** `stop_cap` is a decision: we ran to N_max without ruling in or out; the ship decision is "no" by default and the owner decides whether to extend the cap.
- **Reporting the CI only on the final day.** A sequential test's audit trail is the *sequence* of CIs; dropping the running table hides the interim stops.
- **Mixing one-sided and two-sided semantics across peeks.** A monitor that was two-sided until day 10 and one-sided afterward is two different tests.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. `MEASURE` asks that evaluations be "repeatable, with documented tools and assumptions"; the committed `α`, `σ`, `ρ`, and `MIE` plus the null-coverage simulation operationalize this for a monitor.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** names the family of failures — a naive repeated-fixed-horizon monitor will declare and un-declare "significance" on a random walk, degrading the eval itself.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0015 Evade ML Model` and `AML.T0043 Craft Adversarial Data` motivate the `N_max` cap — an un-bounded monitor is an un-bounded detection window that can be exploited.
- Howard, Ramdas, McAuliffe, Sekhon. *Time-uniform, nonparametric, nonasymptotic confidence sequences.* Annals of Statistics, 2021. The sub-Gaussian CS used above; also covers Bernstein-type variants and the running-mean construction.
- Johari, Pekelis, Walsh. *Always Valid Inference: Bringing Sequential Analysis to A/B Testing.* 2017. Introduces the mSPRT practice used by production experimentation platforms.

<!-- Local exercise context: the paired quality delta with `σ = 0.25`, `ρ = 0.003`, `MIE = 0.01`, `N_max = 1_000_000`, and the hourly peek cadence are illustrative defaults for a user-level quality metric on a chat product. Replace the metric, pre-period `σ`, tuning parameter, MIE, cap, and cadence with your product's own defaults before adopting. The fixed-horizon A/B this monitor relaxes is [exercise-03](../exercise-03-ab-test-with-cuped/SOLUTION.md); the shadow log that most often feeds the monitor is [exercise-02](../exercise-02-shadow-launch-comparison/SOLUTION.md); the observability stack that surfaces the monitor's `stop_*` events as pages is [exercise-05](../exercise-05-production-eval-observability-integration/SOLUTION.md). -->
