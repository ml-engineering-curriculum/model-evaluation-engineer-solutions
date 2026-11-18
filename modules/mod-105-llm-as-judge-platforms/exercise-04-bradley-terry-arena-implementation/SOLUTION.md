## exercise-04 — Bradley-Terry Arena Implementation — Solution

### 1. Solution overview

Pairwise battles produce per-pair verdicts, but a stakeholder usually wants a ranking of N candidates with uncertainty. The exercise asks the learner to **implement a Bradley-Terry (BT) arena**: fit per-candidate skill ratings from pairwise outcomes, quantify uncertainty, and expose the fit as a well-defined artifact.

The Bradley-Terry model is a logistic model of pairwise choice: candidate $i$ beats $j$ with probability

$$
P(i \succ j) = \frac{e^{\theta_i}}{e^{\theta_i} + e^{\theta_j}}
$$

where $\theta_i$ is the (log-scale) skill of candidate $i$. Equivalently, $\text{logit}(P(i \succ j)) = \theta_i - \theta_j$. The fit is a logistic regression with one feature per candidate and the pair outcome as the response; ratings are identified up to an additive constant, so you pin one candidate (or the mean) to zero.

The reference answer has five deliverables:

1. A **data contract** — the pair records consumed by the fit are the swap-collapsed records from [exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md), with ties handled explicitly.
2. A **fit implementation** — a minimal but correct MLE with a regularizer that handles the "never lost" / "never won" degenerate case gracefully.
3. **Uncertainty quantification** — bootstrap CIs on both the ratings and the induced win-rate predictions, with the bootstrap seed pinned.
4. A **publication contract** — a rank table with CIs, an Elo-scale rendering for reader familiarity, and explicit handling of under-sampled candidates.
5. A **guardrail layer** — monotonicity checks against the raw win-rate, cold-start rules, and a refusal to publish when the pair matrix is too sparse or unbalanced.

The adversarial lens is OWASP ML Top 10 **ML08 Model Skewing** — a leaderboard whose pair matrix is concentrated on a few "easy" matchups is trivially gameable; a well-formed BT arena with coverage guardrails is much harder to skew ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). NIST AI RMF `MEASURE` requires measurements to be reliable and documented; the BT arena is the operationalization of a comparative leaderboard metric that is auditable rather than folkloric ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). MITRE ATLAS `Evade ML Model` describes the attacker who optimizes for the specific judge bias a bare win-rate hides but a BT-plus-diagnostics report surfaces ([MITRE ATLAS](https://atlas.mitre.org/)).

### 2. Worked implementation

#### 2.1 Data contract

Each row is a *swap-collapsed* pair outcome produced by the pipeline from [exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md). Ties are retained as a distinct outcome because the BT variant we fit is the **Rao-Kupper tied model** — ties are not dropped, they contribute to the likelihood with a shared `nu` parameter that estimates the "indifference margin."

```python
# arena/types.py
from dataclasses import dataclass
from typing import Literal

Outcome = Literal["x", "y", "tie"]


@dataclass(frozen=True)
class Battle:
    item_id: str
    x: str          # candidate id in slot x of the pair
    y: str          # candidate id in slot y of the pair
    outcome: Outcome
    weight: float = 1.0   # optional per-pair weight (e.g., down-weight stale pairs)
```

Minimum data quality gate before the fit runs:

```yaml
# arena/quality.yaml
require:
  min_total_pairs: 500
  min_pairs_per_candidate: 30
  min_opponents_per_candidate: 5
  max_pairs_single_matchup_share: 0.15
  position_bias:
    slot_a_rate_ci_within: [0.45, 0.55]  # imported from exercise-02 audit
  length_bias:
    beta_len_abs_max: 0.35
```

If any of these fail, the arena refuses to publish and the result card emits a `data_quality_block` banner naming the failed rule. A leaderboard where one candidate has only played itself is not a leaderboard.

#### 2.2 Fit implementation (Rao-Kupper tied Bradley-Terry)

The Rao-Kupper model generalizes BT to ties with a single additional parameter `nu >= 1`:

$$
P(i \succ j) = \frac{e^{\theta_i}}{e^{\theta_i} + \nu\, e^{\theta_j}},\quad
P(i \prec j) = \frac{e^{\theta_j}}{\nu\, e^{\theta_i} + e^{\theta_j}},\quad
P(\text{tie}) = 1 - P(i \succ j) - P(i \prec j)
$$

`nu == 1` recovers the no-tie BT model; `nu > 1` widens the "tie zone." The MLE is a straightforward gradient-ascent problem on `(theta, log_nu)` with the identifiability constraint `mean(theta) = 0`.

```python
# arena/fit.py
import math
from collections import defaultdict
from typing import Iterable
from .types import Battle


def fit_bt_rao_kupper(
    battles: Iterable[Battle],
    candidates: list[str],
    l2: float = 1.0,
    lr: float = 0.05,
    steps: int = 2000,
    tol: float = 1e-7,
) -> dict:
    """Minimal MLE for the Rao-Kupper tied BT model with L2 regularization.

    Returns:
        {
          "theta":   dict[candidate_id, float],   # mean-centered skill
          "nu":      float,                       # tie-zone width, >= 1
          "loglik":  float,                       # log-likelihood at the optimum
          "n_pairs": int,
        }

    L2 on theta prevents infinite skill for never-loss / never-win candidates.
    The value of l2 is small but non-zero; pick it via held-out log-loss, not taste.
    """
    idx = {c: i for i, c in enumerate(candidates)}
    N = len(candidates)
    theta = [0.0] * N
    log_nu = 0.0  # nu = exp(log_nu); bounded >= 1 by max(1, exp(log_nu)) below

    pairs = list(battles)
    n_pairs = len(pairs)
    if n_pairs == 0:
        raise ValueError("No battles to fit")

    def clamp_nu(v):
        return max(1.0, math.exp(v))

    prev_loss = float("inf")
    for step in range(steps):
        gtheta = [0.0] * N
        glog_nu = 0.0
        loss = 0.0
        nu = clamp_nu(log_nu)
        for b in pairs:
            i, j = idx[b.x], idx[b.y]
            ti, tj = theta[i], theta[j]
            ei, ej = math.exp(ti), math.exp(tj)
            # P(x wins) = ei / (ei + nu * ej)
            # P(y wins) = ej / (nu * ei + ej)
            Pxy = ei / (ei + nu * ej)
            Pyx = ej / (nu * ei + ej)
            Ptie = 1.0 - Pxy - Pyx
            Ptie = max(Ptie, 1e-12)
            w = b.weight
            if b.outcome == "x":
                loss -= w * math.log(max(Pxy, 1e-12))
                # dlogL/dti  = 1 - Pxy
                # dlogL/dtj  = -Pxy
                gtheta[i] -= w * (1.0 - Pxy)
                gtheta[j] -= w * (-Pxy)
                # dlogL/dlog_nu = -nu * ej / (ei + nu*ej) = -(Pxy's dependence on nu)
                glog_nu -= w * (-(nu * ej) / (ei + nu * ej))
            elif b.outcome == "y":
                loss -= w * math.log(max(Pyx, 1e-12))
                gtheta[i] -= w * (-Pyx)
                gtheta[j] -= w * (1.0 - Pyx)
                glog_nu -= w * (-(nu * ei) / (nu * ei + ej))
            else:  # tie
                loss -= w * math.log(Ptie)
                # Numerical gradient via chain rule is tedious; a finite-diff is fine for a teaching reference.
                eps = 1e-4
                for k, g_container in ((i, gtheta), (j, gtheta)):
                    theta[k] += eps
                    ei2, ej2 = math.exp(theta[i]), math.exp(theta[j])
                    Pxy2 = ei2 / (ei2 + nu * ej2)
                    Pyx2 = ej2 / (nu * ei2 + ej2)
                    Ptie2 = max(1.0 - Pxy2 - Pyx2, 1e-12)
                    theta[k] -= eps
                    g_container[k] -= w * (math.log(Ptie2) - math.log(Ptie)) / eps
                log_nu += eps
                nu2 = clamp_nu(log_nu)
                Pxy2 = ei / (ei + nu2 * ej)
                Pyx2 = ej / (nu2 * ei + ej)
                Ptie2 = max(1.0 - Pxy2 - Pyx2, 1e-12)
                log_nu -= eps
                glog_nu -= w * (math.log(Ptie2) - math.log(Ptie)) / eps

        # L2 regularization on theta (identifies toward zero).
        for k in range(N):
            loss += 0.5 * l2 * theta[k] * theta[k]
            gtheta[k] += l2 * theta[k]

        # Gradient step.
        for k in range(N):
            theta[k] -= lr * gtheta[k] / n_pairs
        log_nu -= lr * glog_nu / n_pairs

        # Mean-center theta (identifiability constraint).
        m = sum(theta) / N
        for k in range(N):
            theta[k] -= m

        if abs(prev_loss - loss) / max(1.0, abs(prev_loss)) < tol:
            break
        prev_loss = loss

    return {
        "theta": {c: theta[idx[c]] for c in candidates},
        "nu": clamp_nu(log_nu),
        "loglik": -prev_loss,
        "n_pairs": n_pairs,
    }
```

Three implementation notes:

- **L2 with `l2 > 0` is required.** A candidate who wins all its pairs sends its theta to +infinity in the unregularized MLE; a candidate who loses all its pairs sends it to -infinity. L2 is the simplest well-behaved fix. Tune `l2` against held-out log-loss, not by eye.
- **Mean-center every step.** BT ratings are identified up to a constant; without the constraint the fit drifts and the CIs are nonsense.
- **The tie gradient is finite-differenced on purpose.** The closed-form derivative is tedious and error-prone; for a teaching reference the numerical path is a lot easier to review. In production use JAX / torch autograd.

#### 2.3 Elo-scale rendering

Readers are trained to read Elo. Convert the BT skill $\theta$ to an Elo-like scale with the standard affine mapping:

$$
\text{elo}(\theta) = 1000 + \theta \cdot \frac{400}{\ln 10} \approx 1000 + 173.72\,\theta
$$

The 400 / log-10 constant is the Elo convention — a 400-point gap corresponds to an 10:1 win-rate ratio. 1000 is the reference midpoint; any constant is fine as long as it is documented on the result card.

```python
# arena/scale.py
import math

ELO_SCALE = 400.0 / math.log(10.0)


def theta_to_elo(theta: float, base: float = 1000.0) -> float:
    return base + theta * ELO_SCALE
```

The Elo rendering is **for display only**. Downstream code (regression gates, confidence ordering, win-rate predictions) always consumes `theta`.

#### 2.4 Uncertainty: bootstrap CIs

Analytic SEs from the Hessian are fine when the fit is well-conditioned, but with the regularizer and the tied-pair gradient they are brittle. The simpler and more defensible path is a pair-level bootstrap:

```python
# arena/bootstrap.py
import random
from .fit import fit_bt_rao_kupper


def bootstrap_theta(battles, candidates, n_resamples=1000, seed=20261117, **fit_kwargs):
    rng = random.Random(seed)
    pairs = list(battles)
    n = len(pairs)
    draws = {c: [] for c in candidates}
    nu_draws = []
    for _ in range(n_resamples):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        fit = fit_bt_rao_kupper(sample, candidates, **fit_kwargs)
        for c in candidates:
            draws[c].append(fit["theta"][c])
        nu_draws.append(fit["nu"])
    return draws, nu_draws


def summarize(draws, alpha=0.05):
    out = {}
    for c, xs in draws.items():
        xs = sorted(xs)
        lo = xs[int(alpha / 2 * len(xs))]
        hi = xs[int((1 - alpha / 2) * len(xs))]
        out[c] = {"mean": sum(xs) / len(xs), "lo": lo, "hi": hi}
    return out
```

Choices that matter:

- **Resample pairs, not items.** The unit of independence is the pair-outcome. Resampling items double-dips candidates that appear in many pairs for the same item.
- **1000 resamples minimum.** With fewer, the CI quantiles are unstable at the 2.5/97.5 tails.
- **Pin the seed** (`20261117`). The headline CI must be reproducible; changing the bootstrap seed between the point estimate and the published CI is the cheapest way to accidentally p-hack a leaderboard.

#### 2.5 Publication contract

The result card has one table and one diagnostic block.

Rank table (illustrative shape — numbers from running the fit):

| Rank | Candidate | Elo (95% CI) | theta (95% CI) | Pairs | Win-rate (raw) |
|---|---|---|---|---|---|
| 1 | `cand_x` | 1125 (1104, 1148) | 0.72 (0.60, 0.85) | 240 | 0.68 |
| 2 | `cand_y` | 1038 (1020, 1056) | 0.22 (0.11, 0.32) | 220 | 0.58 |
| 3 | `cand_z` | 972 (955, 991) | -0.16 (-0.26, -0.05) | 200 | 0.49 |
| 4 | `cand_w` | 865 (843, 888) | -0.78 (-0.91, -0.65) | 180 | 0.38 |

Diagnostic block:

- `nu` (tie-zone width) and its CI.
- Overlap of CIs between adjacent ranks — ranks separated by less than a non-overlapping CI get a `≈` annotation ("these two cannot be ordered at this sample size").
- Pair-matrix coverage heatmap (candidate × candidate).
- Monotonicity check: for each candidate pair, is `theta_i > theta_j` consistent with `raw_winrate(i vs j) > 0.5`? Report the fraction of pairs where it is; investigate exceptions.
- Position-bias and length-bias audits from [exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md) are reproduced on the arena set.

### 3. Validation steps

1. **Synthetic recovery.** Generate 5 candidates with known `theta_true` drawn from `Normal(0, 0.8)`, simulate 3000 pair outcomes under the Rao-Kupper model with `nu_true = 1.5`, fit. The recovered theta Pearson-correlation with `theta_true` should be > 0.95; `nu` should be within ±0.1 of 1.5. If not, the fit code is wrong before any real data touches it.
2. **Regularization sweep.** For `l2 in {0.1, 1.0, 10.0}`, fit on the synthetic data and compare held-out log-loss on 20% of pairs. Pick the `l2` with the lowest held-out log-loss; log the sweep.
3. **Permutation check.** Shuffle the `outcome` column and refit. All `theta` should collapse near 0 and the Elo gaps should be inside noise. A non-trivial rank table after shuffling is a sign of overfit or a bug in the data contract.
4. **Monotonicity audit.** For every candidate pair with ≥ 20 head-to-head battles, check that the sign of `theta_i - theta_j` matches the sign of `raw_winrate(i vs j) - 0.5`. Non-monotone cases are not automatically bugs (BT has to balance a candidate's results against all opponents), but they deserve an audit note on the result card.
5. **Cold-start refusal.** Add a brand-new candidate with only 5 pairs to the fit. The result pipeline must emit a "cold start" annotation on that row and refuse to assign it a ranked position until `min_pairs_per_candidate` is met.
6. **Bootstrap determinism.** Rerun the bootstrap twice with the same seed. The CI bounds must match to the last reported digit. Changing the seed changes the numbers; never change the seed between estimate and CI.
7. **End-to-end reproducibility.** From the committed `battles.jsonl`, `arena/quality.yaml`, `arena/fit_config.yaml`, and the bootstrap seed, `make arena` must produce byte-identical rank-table CSV and diagnostic PNGs.

### 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Fit consumes swap-collapsed pairs and handles ties explicitly | 2 | Battle records are the collapsed format from exercise-02; ties enter the likelihood via Rao-Kupper, not dropped. |
| R2 | Regularization (L2 or equivalent) is applied and tuned | 1 | `l2` is set, the sweep is logged, and never-win / never-loss candidates do not produce infinite theta. |
| R3 | Ratings are identified via a mean-centering constraint | 1 | `mean(theta) == 0` enforced each step; CIs are reproducible. |
| R4 | Bootstrap CIs with a pinned seed are reported | 2 | `n_resamples >= 1000`; CI bounds are stable across reruns. |
| R5 | Data-quality gates refuse to publish on sparse or biased pair matrices | 1 | `arena/quality.yaml` rules fire with a named `data_quality_block`. |
| R6 | Monotonicity check vs raw head-to-head win-rate is in the diagnostic block | 1 | Non-monotone pairs are listed, not silently absorbed. |
| R7 | Elo rendering is explicit and clearly labeled as display-only | 1 | `173.72` constant is committed; downstream code uses theta, not Elo. |
| R8 | Cold-start candidates are handled explicitly | 1 | Candidates below `min_pairs_per_candidate` get a "cold start" annotation and no final rank. |

**Passing bar:** 7 / 10.

Reviewer checklist:

- [ ] Swap-collapse is applied before the pair records hit the fit (coordinated with exercise-02).
- [ ] The synthetic-recovery test from section 3.1 is in CI.
- [ ] `l2` is chosen via held-out log-loss, not taste.
- [ ] Theta is mean-centered every step.
- [ ] Pair-matrix coverage is reported; near-empty cells are visible.
- [ ] CI half-widths are small enough that the published ranking is interpretable (adjacent ranks either separated or `≈`-annotated).
- [ ] Bootstrap seed is in Git; CI reproducibility is checked.
- [ ] The result card documents the half-credit-for-ties → Rao-Kupper translation so readers do not double-count ties.

### 5. Common mistakes

- **Fitting on raw per-order pairs instead of swap-collapsed pairs.** The fit then absorbs the judge's position bias into the ratings. Always consume the collapsed records.
- **Dropping ties.** The "just drop ties" simplification is tempting but loses 15–40% of the data in many arenas and biases theta in favor of candidates that happen to produce decisive pairs. Use Rao-Kupper.
- **No regularization.** Unregularized MLE on a leaderboard with one or two sweep candidates produces infinite theta and nonsensical CIs.
- **Mean-centering only at the end.** The constraint has to be applied per step or the gradient ascent drifts into a ridge where the loss looks flat.
- **Single Elo rendering without CI.** A naked "1125" Elo number reads as more precise than the fit supports. Always ship the CI; always label the scale.
- **Reporting rank without CI overlap annotation.** Rank 2 vs rank 3 with overlapping CIs is not a defensible ordering; mark it.
- **Bootstrap on items instead of pairs.** Items appear in many pairs; resampling items violates the independence assumption the bootstrap needs.
- **Treating the Elo convention (400 / log10) as physics.** It is a display convention. The underlying model is `theta`; everything else is a constant multiplier.
- **Letting the arena auto-admit new candidates.** New candidates with < `min_pairs_per_candidate` must not get a rank — a one-pair candidate can top the leaderboard trivially.

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires leaderboard metrics to be documented, reliable, and tied to an operational context — a BT fit with CIs and monotonicity checks is the operationalization.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML08 Model Skewing** maps directly to the risk of a pair matrix that is concentrated or missing opponents; coverage guardrails are the defense.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Evade ML Model` captures the attacker who writes responses optimized for the judge's bias; the position/length audits from exercise-02 are what the arena imports to make that attack visible.

<!-- Local exercise context: the Elo midpoint of 1000, the l2 default of 1.0, and the pair-matrix thresholds in `arena/quality.yaml` are illustrative starting points. Re-derive them against your own arena data and stakes before adopting; the synthetic-recovery test is the non-negotiable piece. -->
