# exercise-03 — A/B Experiment With CUPED Variance Reduction — Solution

## 1. Solution overview

An A/B experiment on a production model earns the right to ship the candidate on the only distribution that matters: the actual user traffic, scored by the actual product metric. The hard problem is not running the experiment; it is **powering it**. The outcome metrics that matter — session satisfaction, task completion, 7-day retention, revenue per session — have high variance and long tails. The observable effect of a good candidate is typically a few percentage points; the week-over-week noise on the same metric is often larger. An under-powered A/B either demands an infeasible sample or declares no effect when one exists.

**CUPED** — Controlled-experiment Using Pre-Experiment Data (Deng, Xu, Kohavi, Walker, 2013) — is the standard variance-reduction technique for online experiments. The idea is simple: for each unit (a user, a session), you have a pre-experiment period during which both arms behaved identically. The unit's outcome during the experiment is highly correlated with the same unit's pre-experiment outcome. If you subtract off a scaled-down version of the pre-experiment signal, you remove the between-unit variance that was already present before the experiment started, without introducing bias. The result is the same ATE, a tighter CI, and an experiment that fires in days instead of weeks.

The reference answer has five deliverables:

1. A **randomization plan** — the unit (user_id vs. session vs. request), the hash salt, the split, and the committed bucketing function.
2. A **pre-experiment covariate table** — one row per unit with a committed pre-period window, the covariate value `X_i`, and the exposure timestamp.
3. A **CUPED estimator** — compute `theta_hat = Cov(Y, X) / Var(X)`, form `Y_cuped = Y - theta_hat * (X - E[X])`, estimate ATE on `Y_cuped`, and report a variance-reduction ratio.
4. A **power analysis** — the sample size required to detect a declared minimum detectable effect, first at full variance, then at the CUPED-reduced variance, with the committed alpha and power.
5. An **experiment report** — the point estimate, CI (with and without CUPED), p-value, MDE at observed n, and a reality check that the pre-period means balance between arms (SRM + covariate balance).

This maps to the NIST AI RMF `MEASURE` function, which requires documented statistical methods and operational context ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML09 Output Integrity Attacks** — a biased randomizer or a covariate collected from inside the experiment window is an attack on the eval, not on the model ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS technique `AML.T0043 Craft Adversarial Data` motivates the pre-experiment freeze — any post-exposure signal that leaks into the covariate is a vector for inflating variance reduction with a spurious correlation ([MITRE ATLAS](https://atlas.mitre.org/)).

The CUPED method is the published Deng–Xu–Kohavi–Walker technique; its validity depends on the covariate being measured **strictly before** the exposure. The reference below is to the authors' original paper.

## 2. Worked implementation

### 2.1 Randomization unit and bucketing

The randomization unit is the first design decision. Two rules:

- **The unit must be the smallest independent entity for which outcomes are measured.** For a chat product where users return across sessions, this is the `user_id`, not the session or the request. Randomizing on sessions when a user returns in multiple sessions contaminates the arms.
- **The bucketing is a committed function of (unit_id, experiment_id, salt).** No lookups, no databases; given the three, the bucket is deterministic.

```python
"""Bucketing function: deterministic, uniform, split-stable across hashes."""

from __future__ import annotations
import hashlib


def bucket(unit_id: str, experiment_id: str, salt: str) -> float:
    """Return a uniform [0,1) bucket. Salt is committed per experiment so a
    salt reuse across experiments cannot create correlated assignments."""
    h = hashlib.blake2b(f"{experiment_id}:{salt}:{unit_id}".encode(), digest_size=8)
    return int(h.hexdigest(), 16) / 2**64


def assign(unit_id, experiment_id, salt, splits):
    """splits: list[(arm_name, cumulative_bound)], e.g.
       [('control', 0.5), ('treatment', 1.0)]."""
    b = bucket(unit_id, experiment_id, salt)
    for arm, bound in splits:
        if b < bound:
            return arm
    return splits[-1][0]  # defensive
```

Rules:

- **One experiment id per experiment.** Re-using an id with a new split silently changes assignments for units that returned.
- **Hash with enough bits.** 8-byte hashes are ≥2^−64 uniform; truncating to 4 bytes is a convenience that creates visible drift in small splits.
- **Record the salt and the splits in the manifest.** A reviewer who finds the manifest must be able to re-derive every unit's assignment.

### 2.2 Pre-experiment covariate `X_i`

`X_i` is the per-unit pre-period value of the same (or a correlated) outcome metric as `Y_i`:

- For a revenue-per-session metric `Y`, use the unit's mean revenue over a committed pre-period (e.g., the 28 days immediately preceding the experiment start).
- For a "task completion" outcome, use the unit's pre-period completion rate.
- For a binary 0/1 outcome, use the pre-period mean of the same binary.

The **pre-period ends strictly before the exposure timestamp** per unit. A user who first encounters the experiment on day 3 has a pre-period that ends on day 2, not day 0. Mixing the two produces a covariate that already partially reflects treatment.

```python
"""Load the pre-experiment covariate table; validate the freeze window."""

import pandas as pd


def load_covariates(path: str, exp_start_ts: str, pre_window_days: int) -> pd.DataFrame:
    df = pd.read_parquet(path)
    required = {"unit_id", "exposure_ts", "X", "pre_window_start", "pre_window_end"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"missing columns: {missing}")
    bad = df[df["pre_window_end"] >= df["exposure_ts"]]
    if len(bad):
        raise ValueError(f"{len(bad)} units have pre-window extending past exposure")
    return df
```

Rules the covariate step enforces:

- **Pre-window ends before exposure for every unit.** The validator refuses the file otherwise.
- **The covariate is observed, not predicted.** A model-predicted score for each unit is not a pre-experiment observation; it is a side channel that can leak the treatment if the predictor was trained on data that includes treatment.
- **Missing covariates have a committed imputation.** Default: impute with the arm's mean `X`. The variance-reduction gain shrinks, but no bias is introduced; dropping rows with missing `X` is a form of selection and biases the ATE.
- **One covariate per unit, one `X`.** If multiple pre-period values exist, aggregate (mean, sum, last) with a committed function. Do not stack covariates silently.

### 2.3 CUPED estimator

The two-liner at the heart of the method:

```python
"""CUPED: compute Y_cuped = Y - theta * (X - mean(X)).

theta = Cov(Y, X) / Var(X), estimated on the union of both arms. Under the
null that X is not caused by treatment (enforced by the pre-period freeze),
Y_cuped is unbiased for the treatment effect on Y and has lower variance
whenever Corr(Y, X) is nonzero."""

from __future__ import annotations
import numpy as np


def theta_from_pooled(Y: np.ndarray, X: np.ndarray) -> float:
    var_x = np.var(X, ddof=1)
    if var_x <= 0:
        return 0.0
    return float(np.cov(Y, X, ddof=1)[0, 1] / var_x)


def apply_cuped(Y: np.ndarray, X: np.ndarray, theta: float) -> np.ndarray:
    return Y - theta * (X - X.mean())


def ate_with_cuped(
    y_t: np.ndarray, x_t: np.ndarray,
    y_c: np.ndarray, x_c: np.ndarray,
) -> dict:
    Y = np.concatenate([y_t, y_c])
    X = np.concatenate([x_t, x_c])
    theta = theta_from_pooled(Y, X)
    y_t_cuped = apply_cuped(y_t, x_t, theta)
    y_c_cuped = apply_cuped(y_c, x_c, theta)
    ate = float(y_t_cuped.mean() - y_c_cuped.mean())
    # Welch-style SE on CUPED-adjusted arrays:
    se = float(np.sqrt(
        y_t_cuped.var(ddof=1) / len(y_t_cuped)
        + y_c_cuped.var(ddof=1) / len(y_c_cuped)
    ))
    # Variance reduction ratio vs no-CUPED SE:
    se_raw = float(np.sqrt(
        y_t.var(ddof=1) / len(y_t) + y_c.var(ddof=1) / len(y_c)
    ))
    vr = 1.0 - (se / se_raw) ** 2 if se_raw > 0 else 0.0
    from scipy.stats import norm
    z = ate / se if se > 0 else 0.0
    p_two_sided = 2 * (1 - norm.cdf(abs(z)))
    return {
        "ate": ate,
        "se": se,
        "ci_lo": ate - 1.96 * se,
        "ci_hi": ate + 1.96 * se,
        "theta": theta,
        "variance_reduction": vr,     # fraction of variance removed
        "p_value": float(p_two_sided),
        "n_treatment": int(len(y_t)),
        "n_control": int(len(y_c)),
    }
```

Design rules worth calling out:

- **Estimate `theta` on the pooled sample**, not per arm. Per-arm `theta` can absorb treatment effect into the regressor and shrink the ATE (bias). Pooled `theta` is the published method's prescription.
- **Center `X` by its sample mean.** Centering inside `apply_cuped` (`X - X.mean()`) rather than hand-picking a constant keeps the mean of `Y_cuped` equal to the mean of `Y` across the pooled sample.
- **Report both CUPED SE and raw SE.** The variance-reduction ratio is `1 - (SE_cuped / SE_raw)^2`; a value near zero means the covariate was weakly correlated and CUPED did not help. Committing this to the report prevents a quiet overclaim.
- **CUPED does not fix a biased randomizer.** If SRM (sample ratio mismatch) is triggered, CUPED is a distraction; fix the randomizer first.
- **Clip `X` for heavy-tailed metrics.** If `X` is revenue-per-session, a whale with 100× the median breaks the finite-sample `theta` estimate. A committed winsorization at a pre-period percentile (e.g., 99.9) is standard and documented.

### 2.4 Power analysis

The power computation determines the sample size `n_per_arm` needed to detect a declared minimum detectable effect `MDE` at alpha and power.

Two-sample (Welch), equal allocation, large-sample approximation:

```
n_per_arm ≈ (z_{1-α/2} + z_{power})^2 * (σ_t^2 + σ_c^2) / MDE^2
```

CUPED reduces the effective variance by the factor `(1 - ρ^2)` where `ρ = Corr(Y, X)` on the pooled sample. The required sample size scales linearly with variance, so:

```
n_per_arm_cuped ≈ n_per_arm_raw * (1 - ρ^2)
```

```python
"""Pre-experiment power analysis.

Call before the experiment starts, with sigma^2 and rho estimated from the
pre-period on a representative traffic sample (the SAME traffic we expect
to see during the experiment; never on a cherry-picked subset)."""

from __future__ import annotations
import math
from scipy.stats import norm


def required_n_per_arm(mde: float, sigma2: float, alpha: float, power: float) -> int:
    z_alpha = norm.ppf(1 - alpha / 2)
    z_power = norm.ppf(power)
    n = (z_alpha + z_power) ** 2 * 2 * sigma2 / mde**2
    return int(math.ceil(n))


def cuped_adjusted_n(n_raw: int, rho: float) -> int:
    rho = max(-0.999, min(0.999, rho))
    return int(math.ceil(n_raw * (1 - rho**2)))
```

Rules:

- **MDE is declared, not discovered.** A post-hoc MDE pinned to whatever number made the result significant is cherry-picking. The MDE is signed off at experiment design time and committed to the manifest.
- **Pre-period `ρ` is a pre-committed estimate.** A pre-period `ρ` computed during the experiment on half the data biases the chosen variance in unknown directions.
- **If `ρ^2` is tiny (<0.1), CUPED is not worth the complexity.** Report the raw ATE; CUPED is a tool, not a ritual.
- **The sample size is in units, not requests.** A user with 40 sessions is one unit. Powering as if 40 sessions were 40 independent units is a textbook CI understatement.

### 2.5 Sample-ratio-mismatch (SRM) and covariate-balance checks

Before trusting a CUPED result, two checks must pass:

- **SRM.** Observed `n_t / (n_t + n_c)` against the declared split (e.g., 0.5). Use a two-sided chi-squared with Yates correction, or a two-sided Fisher exact for small cells. A p-value below a pre-declared threshold (e.g., 0.001) halts the analysis; the randomizer is broken.
- **Covariate balance.** Mean of `X` in treatment vs. control; the difference should be consistent with zero. A standardized mean difference above 0.1 is a flag; above 0.2 is a halt. CUPED does not rescue a biased randomizer; it is a variance tool, not a bias tool.

Both checks are in the pre-flight step of the analyzer, before the CUPED calculation runs:

```python
def srm_check(n_t: int, n_c: int, expected_share: float, alpha: float = 0.001) -> dict:
    from scipy.stats import chisquare
    total = n_t + n_c
    expected_t = expected_share * total
    expected_c = total - expected_t
    chi2, p = chisquare([n_t, n_c], f_exp=[expected_t, expected_c])
    return {"chi2": float(chi2), "p": float(p), "passed": p >= alpha}


def covariate_balance(x_t, x_c) -> dict:
    import numpy as np
    pooled_sd = np.sqrt(0.5 * (np.var(x_t, ddof=1) + np.var(x_c, ddof=1)))
    smd = (x_t.mean() - x_c.mean()) / pooled_sd if pooled_sd > 0 else 0.0
    return {"smd": float(smd), "passed": abs(smd) < 0.1}
```

### 2.6 Report and manifest

`ab_report_<run_id>.md`:

```markdown
# Experiment product-llm-v7 (exp_2026-11-20) — Day 7

**Decision:** ship (p<0.001; CI excludes zero; SRM ok; covariate balance ok)

## Pre-flight checks
| Check | Result |
|---|---|
| SRM (expected 50/50)  | n_t=120_412, n_c=120_388; chi2=0.002; p=0.961 ✅ |
| Covariate balance SMD | +0.012 ✅ |

## Primary outcome: revenue_per_user_7d (log1p-transformed)
|  | Treatment | Control | ATE | 95% CI | p-value |
|---|---|---|---|---|---|
| Raw mean  | 1.482 | 1.457 | +0.025 | [+0.018, +0.032] | 1e-11 |
| CUPED-adjusted | 1.482 | 1.457 | +0.025 | [+0.021, +0.029] | 3e-26 |

**Variance reduction:** 68% (ρ ≈ 0.82 on pre-period)

## Guardrail metrics
| Metric | Direction | ATE | CI |
|---|---|---|---|
| p95_latency_ms | lower_better | +4 ms | [+1, +7] ⚠ within guardrail |
| refusal_rate   | lower_better | +0.003 | [+0.002, +0.005] ⚠ within guardrail |
```

Manifest `ab_run.yaml`:

```yaml
run_id: exp_2026-11-20_product-llm-v7
experiment_id: exp_2026-11-20
salt: <salt committed at design time>
splits: [["control", 0.5], ["treatment", 1.0]]
window:
  start: 2026-11-13T00:00:00Z
  end:   2026-11-20T00:00:00Z
unit: user_id
pre_period_window_days: 28
primary_metric:
  name: revenue_per_user_7d
  transform: log1p
  mde: 0.015
  alpha: 0.05
  power: 0.8
  pre_period_rho_estimate: 0.80
cuped:
  theta_estimation: pooled
  centering: sample_mean
  winsorize_X_at: {q_lo: 0.001, q_hi: 0.999}
guardrails:
  - metric: p95_latency_ms
    ceiling: 10
    direction: lower_better
  - metric: refusal_rate
    ceiling: 0.005
    direction: lower_better
pre_flight_thresholds:
  srm_alpha: 0.001
  smd_halt_threshold: 0.2
seed: 20261120
```

## 3. Validation steps

1. **Bucketing determinism.** Given `(unit_id, experiment_id, salt)`, `assign(...)` always returns the same arm. A snapshot of 10^6 unit ids is committed and the hash is verified in CI.
2. **Covariate pre-freeze.** For every unit, `pre_window_end < exposure_ts`. Validator refuses the parquet otherwise.
3. **Winsorization applied.** `X` values at or beyond committed quantiles are clipped; the `theta` estimate uses winsorized `X`.
4. **`theta` on pooled sample.** A unit test constructs two arms with known `Cov(Y,X) / Var(X)` on the pooled sample and asserts `theta_from_pooled` matches analytically.
5. **CUPED preserves the ATE under the null.** Simulate `Y_t = Y_c + 0` with correlated `X`; `ate_with_cuped` is unbiased for 0 across many seeds.
6. **CUPED shrinks the CI.** On a synthetic dataset with `ρ = 0.7`, the CUPED CI is narrower than the raw CI by the predicted factor `(1 - ρ^2)`.
7. **Variance reduction is reported.** `variance_reduction` in the result object matches `1 - (se_cuped / se_raw)^2`.
8. **SRM halts the analysis.** A synthetic 55/45 split triggers `passed=False` and the analyzer refuses to produce a CUPED result.
9. **Covariate-balance halts the analysis.** A synthetic treatment arm with a 0.3-SD shift in `X` triggers the halt threshold.
10. **Guardrail enforcement.** A synthetic candidate with latency over the ceiling fails the guardrail check even if the primary is significant.
11. **Reproducibility.** Rerun of `analyzer.py` on the same event log + covariate table produces byte-identical point estimates, CIs, p-values, and variance-reduction ratio.

## 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Randomization is deterministic, hashed, salted, and committed | 1 | `assign` is tested on a snapshot; salt in manifest. |
| R2 | Unit of randomization is pinned and matches the outcome unit | 1 | Manifest `unit`; outcomes aggregated to the same grain. |
| R3 | Pre-period covariate is validated to end before exposure | 2 | Loader refuses files that violate; test covers a unit-level overlap. |
| R4 | CUPED `theta` is estimated on pooled sample with centered `X` | 2 | `theta_from_pooled`; unit test on analytical dataset. |
| R5 | Variance-reduction ratio is reported and non-cherry-picked | 1 | Report includes both raw and CUPED CIs and the `ρ` used in the power calc. |
| R6 | Pre-flight checks (SRM, SMD) halt the analysis on failure | 1 | Synthetic 55/45 split test passes the halt. |
| R7 | Guardrail metrics are declared with signed ceilings and enforced | 1 | Manifest `guardrails`; ship decision requires guardrails pass. |
| R8 | Manifest pins unit, salt, window, MDE, alpha, power, pre-period `ρ`, winsorization, seed | 1 | `ab_run.yaml` has every field; rerun is byte-identical. |

**Passing bar:** 7 / 10. R3 and R4 are non-negotiable — a covariate that leaks treatment is a biased ATE, and a per-arm `theta` absorbs the treatment effect.

Reviewer checklist:

- [ ] Hashing uses committed salt; assignments reproducible from unit id + manifest.
- [ ] Covariate pre-window strictly ends before per-unit exposure.
- [ ] `theta` is pooled, `X` is centered by sample mean, winsorization applied.
- [ ] Report includes raw CI, CUPED CI, variance-reduction ratio, and the `ρ` from the power calc.
- [ ] SRM and SMD checks run before CUPED; failure halts the analysis.
- [ ] Guardrail metrics are reported with CIs; a guardrail breach blocks the ship decision.
- [ ] Manifest includes unit, salt, window, MDE, alpha, power, seed.
- [ ] Rerun of the analyzer produces byte-identical outputs.

## 5. Common mistakes

- **Session-level randomization with user-level outcomes.** Users return, sessions don't. CIs understate the real noise; "significant" results do not replicate. Randomize on the unit that owns the outcome.
- **Covariate from inside the experiment window.** A `X` computed on day 3 of a 14-day experiment already reflects some treatment. The ATE is biased, usually in the direction that makes the treatment look better.
- **Per-arm `theta`.** `theta_t` learned on the treated arm absorbs part of the ATE and shrinks the reported effect. Pool.
- **Dropping rows with missing covariate.** The dropped rows are not missing at random — they are often new users, exactly the population the launch targets. Impute with the arm mean; report the impute rate.
- **Winsorization chosen to maximize `ρ`.** The clipping quantiles are declared at design time; shopping them for significance inflates false-positive rate.
- **Peeking without a sequential test.** CUPED buys power; it does not license peeking. Repeatedly checking the two-sided z at each day with a 0.05 alpha inflates the false-positive rate. Use a sequential test ([exercise-04](../exercise-04-sequential-testing-for-continuous-monitoring/SOLUTION.md)) if you need to peek.
- **Ignoring SRM.** A broken randomizer makes every downstream statistic a lie; CUPED does not fix it. SRM check runs first and halts the analysis.
- **Primary metric chosen after seeing the data.** A primary that was a guardrail yesterday is now the headline because it moved. Pin the primary metric in the manifest at design time.
- **Reporting ATE without a CI.** A point estimate is a mood; the CI is the decision.
- **Missing variance-reduction context.** Reporting the CUPED CI without the `ρ` or the reduction ratio overclaims the method's role; a small `ρ` means CUPED added noise to the pipeline for no gain.
- **Treating CUPED as bias correction.** CUPED is an unbiased estimator of the ATE under random assignment; it does not control for confounding in an observational setting.
- **Post-hoc MDE.** "We could detect 1.2pp" is a sentence written after the result is known; the real MDE was declared at design time.
- **Unit mismatch between covariate and outcome.** Covariate is per user, outcome is per session; the CUPED subtraction is nonsensical. Align the units before the subtraction.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. `MEASURE` asks for documented statistical methods and operational context; the CUPED manifest and the pre-committed power analysis are the direct operationalization.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** motivates the covariate-freeze rule and the halting SRM check — a biased randomizer or a leaky covariate is an attack on the eval.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0043 Craft Adversarial Data` motivates the pre-period freeze and the ban on post-hoc MDE shopping.
- Deng, Xu, Kohavi, Walker. *Improving the Sensitivity of Online Controlled Experiments by Utilizing Pre-Experiment Data.* WSDM 2013. The CUPED method, including the pooled-theta prescription and the proof that it is unbiased under random assignment.

<!-- Local exercise context: the `revenue_per_user_7d` primary metric, the 28-day pre-period, the 50/50 split, and the specific guardrail ceilings (p95 latency +10 ms, refusal rate +0.5pp) are illustrative defaults for a chat product with a revenue-adjacent outcome. Replace the metric, pre-period, split, and guardrails with your product's own experimental defaults before adopting. The offline gate that gates eligibility for this A/B is [exercise-01](../exercise-01-offline-regression-suite-with-gates/SOLUTION.md); the shadow-launch comparison that validates the candidate before the online A/B is [exercise-02](../exercise-02-shadow-launch-comparison/SOLUTION.md); the sequential test to support early stopping and peeking during the A/B is [exercise-04](../exercise-04-sequential-testing-for-continuous-monitoring/SOLUTION.md). -->
