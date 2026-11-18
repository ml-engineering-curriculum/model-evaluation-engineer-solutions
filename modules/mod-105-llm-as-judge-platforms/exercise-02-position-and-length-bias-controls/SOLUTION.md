## exercise-02 — Position and Length Bias Controls — Solution

### 1. Solution overview

Pairwise LLM-as-judge is a biased measurement by default. Two well-documented biases dominate at production scale:

- **Position bias** — the judge systematically favours one slot (usually the first, sometimes the second) regardless of content. A judge that would pick response X 60% of the time when X is in slot A and only 40% when X is in slot B is not measuring quality; it is measuring slot.
- **Length / verbosity bias** — the judge systematically prefers longer responses, even when the longer response is not better on the rubric. This bias is asymmetric: it almost never favours the shorter response.

The exercise asks the learner to build **controls that convert a raw biased judge into a usable measurement instrument**. The reference answer has four deliverables:

1. A **position-swap wrapper** that runs each pair in both orderings and collapses the result into a single verdict / win-rate; the raw per-order data is retained for diagnosis.
2. A **position-bias audit** that estimates the residual bias and refuses to publish numbers when the bias exceeds a committed threshold.
3. A **length-bias audit** that regresses the judge's verdict on the length delta between responses, reports the slope with a CI, and (optionally) applies a **length-controlled win-rate** correction.
4. A **reporting contract** that surfaces the raw win-rate, the swap-collapsed win-rate, the length-controlled win-rate, and the bias diagnostics together so a reviewer can see what the controls did.

This maps to the NIST AI RMF `MEASURE` function, which requires measurements to be "reliable under non-material perturbations" and "tied to an identified operational context" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). A judge that moves its answer when you swap positions or extend the response with filler is failing that bar. OWASP ML Top 10 **ML01 Input Manipulation** is the direct lens — an attacker who knows the judge is verbose-biased can pad their response with correct-sounding filler to flip the verdict ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `LLM Prompt Injection` and `Craft Adversarial Data` describe the attacker techniques these controls defend against ([MITRE ATLAS](https://atlas.mitre.org/)).

The rubric and prompts this exercise builds on are the ones from [exercise-01](../exercise-01-absolute-and-pairwise-rubric-design/SOLUTION.md).

### 2. Worked implementation

#### 2.1 Position-swap wrapper

Every pair of candidate responses `(x, y)` is evaluated twice: once with `x` in slot A and `y` in slot B, once with `x` in slot B and `y` in slot A. Both orderings are run with the **same judge model, same decoding, same seed**; only the slot assignment changes.

```python
# pairwise_controls/swap.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Literal

Verdict = Literal["A", "B", "tie"]
CandKey = str  # e.g., "candidate_x", "candidate_y"


@dataclass(frozen=True)
class PerOrderResult:
    order: Literal["xy", "yx"]  # xy = x->A, y->B. yx = x->B, y->A.
    verdict: Verdict
    judge_raw: dict               # full JSON from the judge for forensics


@dataclass(frozen=True)
class SwapCollapsed:
    item_id: str
    x: CandKey
    y: CandKey
    per_order: tuple[PerOrderResult, PerOrderResult]
    collapsed_winner: Literal["x", "y", "tie"]
    inconsistency: bool  # True when the two orders disagree about the winner


def collapse(per_order: tuple[PerOrderResult, PerOrderResult]) -> tuple[Literal["x", "y", "tie"], bool]:
    """Collapse a pair of per-order verdicts into a single x/y/tie verdict.

    Mapping per order:
        xy:  A -> x, B -> y, tie -> tie
        yx:  A -> y, B -> x, tie -> tie
    Agreement rule:
        - Both orders pick x        -> x
        - Both orders pick y        -> y
        - Both orders say tie        -> tie
        - One picks x, one picks y   -> tie, inconsistency=True
        - One picks a side, one tie  -> tie, inconsistency=False (judge is not confident both ways)
    """
    def norm(r: PerOrderResult) -> Literal["x", "y", "tie"]:
        if r.verdict == "tie":
            return "tie"
        if r.order == "xy":
            return "x" if r.verdict == "A" else "y"
        return "y" if r.verdict == "A" else "x"

    a, b = norm(per_order[0]), norm(per_order[1])
    if a == b:
        return a, False
    if {a, b} == {"x", "y"}:
        return "tie", True
    return "tie", False  # one side + one tie -> tie, but not a direct contradiction
```

Properties the collapse rule enforces:

- A pair only wins if the judge picks the same candidate in both orderings. "A judge that agrees with itself" is the minimum bar.
- A direct contradiction (`xy -> x`, `yx -> y`) is counted as a tie **and** flagged as an `inconsistency` — those are the pairs that drive the position-bias estimate (section 2.3).
- A side-vs-tie split collapses to tie without the inconsistency flag, because the judge is signalling it isn't sure.

#### 2.2 Win-rate aggregation

```python
# pairwise_controls/winrate.py
from collections import Counter
from .swap import SwapCollapsed


def collapsed_winrate(results: list[SwapCollapsed], candidate: str) -> dict:
    """Swap-collapsed win-rate for `candidate` across a set of pairs."""
    wins = ties = losses = 0
    for r in results:
        if candidate not in (r.x, r.y):
            continue
        winner = r.collapsed_winner
        if winner == "tie":
            ties += 1
        elif (winner == "x" and r.x == candidate) or (winner == "y" and r.y == candidate):
            wins += 1
        else:
            losses += 1
    total = wins + ties + losses
    return {
        "wins": wins, "ties": ties, "losses": losses, "total": total,
        # Half-credit-for-ties is the conventional arena convention; note that half-credit
        # changes the interpretation and must be labeled on the result card.
        "winrate": (wins + 0.5 * ties) / total if total else float("nan"),
    }
```

Pair aggregation choices:

- **Half-credit for ties.** Ties happen by design when the tie rule from the rubric fires. Counting ties as half-wins is the conventional arena convention and matches a Bradley-Terry fit that treats ties as draws (see [exercise-04](../exercise-04-bradley-terry-arena-implementation/SOLUTION.md)). Label this on the result card — a reader who expects "wins / (wins + losses)" will misread the number otherwise.
- **`total` is counted after collapse.** Each pair contributes one data point to the win-rate, not two. Counting both orderings double-counts biased pairs.

#### 2.3 Position-bias audit

The audit estimates two quantities:

- **Order-flip rate** — the fraction of pairs where the two orderings disagree on a side (contradictions, not side-vs-tie). This is the raw amount of position-bias noise.
- **Slot-A preference** — across *all* judgements (both orderings combined), how often the judge picks slot A. If the judge were position-neutral this would be 50% ± sampling noise. A persistent deviation from 50% is position bias.

```python
# pairwise_controls/position_audit.py
from statistics import NormalDist
from .swap import SwapCollapsed


def position_audit(pairs: list[SwapCollapsed]) -> dict:
    flips = sum(1 for p in pairs if p.inconsistency)
    n = len(pairs)
    order_flip_rate = flips / n if n else float("nan")

    # Slot-A preference across both orderings of every pair (so each pair contributes 2).
    a_picks = 0
    total = 0
    for p in pairs:
        for per in p.per_order:
            if per.verdict in ("A", "B"):
                total += 1
                if per.verdict == "A":
                    a_picks += 1
    slot_a_rate = a_picks / total if total else float("nan")

    # Wilson score 95% CI for slot_a_rate.
    z = NormalDist().inv_cdf(0.975)
    if total:
        p = slot_a_rate
        denom = 1 + z * z / total
        centre = (p + z * z / (2 * total)) / denom
        half = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / denom
        ci = (centre - half, centre + half)
    else:
        ci = (float("nan"), float("nan"))

    return {
        "n_pairs": n,
        "order_flip_rate": order_flip_rate,
        "slot_a_rate": slot_a_rate,
        "slot_a_ci_95": ci,
    }
```

Pre-committed publication thresholds (edit the YAML, don't change these inline):

```yaml
# pairwise_controls/thresholds.yaml
position_bias:
  # Refuse to publish the pairwise win-rate when any of these fire.
  max_order_flip_rate: 0.10       # > 10% contradictions = judge is too noisy to trust
  slot_a_rate_warn:   [0.45, 0.55] # inside = healthy
  slot_a_rate_block:  [0.40, 0.60] # outside = block publication; switch judge or re-prompt

length_bias:
  # Residual length coefficient from the logistic regression in section 2.4.
  # |beta_len| is in units of "log-odds per 100 chars of length delta".
  beta_abs_warn:  0.15
  beta_abs_block: 0.35
```

The thresholds are examples drawn from the rubric this exercise ships with — they are not universal. Re-derive them against your own calibration data in [exercise-03](../exercise-03-judge-vs-human-calibration-study/SOLUTION.md) before porting to production.

#### 2.4 Length-bias audit

The audit fits a logistic regression of the swap-collapsed verdict on the signed length delta. `delta_len_chars = len(x) - len(y)` (signed so positive means x is longer). The outcome is `y_i = 1` when the collapsed winner is `x`, `0` when `y`, dropped when tie.

```python
# pairwise_controls/length_audit.py
import math
from .swap import SwapCollapsed


def length_features(r: SwapCollapsed, text_lookup) -> tuple[float, int] | None:
    if r.collapsed_winner == "tie":
        return None
    lx = len(text_lookup[r.item_id][r.x])
    ly = len(text_lookup[r.item_id][r.y])
    delta_100 = (lx - ly) / 100.0  # per 100 chars
    y = 1 if r.collapsed_winner == "x" else 0
    return delta_100, y


def fit_length_logit(pairs, text_lookup, n_steps=400, lr=0.1):
    """Vanilla logistic regression: y ~ logit(beta0 + beta_len * delta_len).

    Intentionally minimal — a full statsmodels fit is fine in practice, but this
    is enough to ship the audit without a heavy dependency.
    """
    X, Y = [], []
    for r in pairs:
        f = length_features(r, text_lookup)
        if f is None:
            continue
        X.append(f[0]); Y.append(f[1])
    if not X:
        return {"beta_len": float("nan"), "beta0": float("nan"), "n": 0}

    b0 = b1 = 0.0
    n = len(X)
    for _ in range(n_steps):
        g0 = g1 = 0.0
        for xi, yi in zip(X, Y):
            p = 1.0 / (1.0 + math.exp(-(b0 + b1 * xi)))
            g0 += (p - yi)
            g1 += (p - yi) * xi
        b0 -= lr * g0 / n
        b1 -= lr * g1 / n

    # Wald-ish SE via the observed information (diagonal; good enough for a diagnostic).
    I00 = I11 = 0.0
    for xi in X:
        p = 1.0 / (1.0 + math.exp(-(b0 + b1 * xi)))
        w = p * (1 - p)
        I00 += w
        I11 += w * xi * xi
    se1 = (1.0 / I11) ** 0.5 if I11 > 0 else float("nan")

    return {"beta_len": b1, "beta_len_se": se1, "beta0": b0, "n": n}
```

Interpreting the fit:

- `beta_len` is the log-odds of `x` winning per 100 characters of extra length. A statistically significant positive `beta_len` is the direct signature of verbosity bias.
- `beta_len_se` gives a Wald CI (`beta ± 1.96 * se`). Treat the CI as a diagnostic, not a hypothesis test — for a block/warn decision you want an *effect size* rule from `thresholds.yaml`, not a p-value.
- The length-controlled win-rate for `x` adjusts each pair to the length-neutral prediction: `p_adj(x) = sigmoid(beta0 + 0 * beta_len) = sigmoid(beta0)` — i.e., the win-rate the judge would report if both responses were the same length. It's a crude correction, but the alternative is leaving length bias unacknowledged.

Report *both* the raw swap-collapsed win-rate and the length-controlled win-rate side by side. Picking one as "the answer" and hiding the other reads as cherry-picking in review.

#### 2.5 Length-matching at generation time (preferred control)

The best control for verbosity bias is not a correction after the fact — it is **not letting the responses diverge in length in the first place**. Two options:

- **Equal budget.** Generate both candidates with the same `max_new_tokens` and the same stop sequences.
- **Length-matched pairs.** Drop pairs where `|len(x) - len(y)| / max(len(x), len(y)) > 0.25`. You lose 10–25% of pairs; the remaining set is where the judge is actually comparing content.

Length-matching is cheap; it is strictly better than regressing bias out after the fact. Reserve the regression audit for **monitoring** — if length-matching is in place and `beta_len` is still non-zero, something upstream is drifting.

### 3. Validation steps

1. **Synthetic-position-bias injection.** Build a small fixture (50 pairs) of *known-equivalent* responses — paraphrases that the rubric should call a tie. Run them through the pipeline. The order-flip rate should be ≤ `max_order_flip_rate`; the slot-A preference should be inside `slot_a_rate_warn`. If either fails on this fixture, the judge / prompt is broken before any real data is collected.
2. **Synthetic-length-bias injection.** Take 100 pairs where the rubric score is tied, then pad one side with on-topic filler to lengthen it by 50%. Run the length audit. `beta_len` should be small; if it is large on this fixture, the judge is verbosity-biased and length-matching at generation is required before publishing any pairwise win-rate.
3. **Swap-collapse unit tests.** Enumerate all 9 combinations of `(xy_verdict, yx_verdict)` over `{A, B, tie}` and assert the collapse rule gives the expected `(collapsed_winner, inconsistency)` for each. The collapse rule is the single most error-prone part of the pipeline; don't ship it without the matrix test.
4. **Seed-pinned re-run.** Fix the judge's `seed` and decoding; rerun the same inputs twice. The per-order verdicts and the collapse must be identical. If they drift, something upstream is nondeterministic (temperature > 0, tool-use randomness, a sampled retry).
5. **Threshold gate.** Wire the audit into the result pipeline so the headline win-rate is only emitted when both `position_bias` and `length_bias` thresholds pass. A warn-level breach surfaces a banner; a block-level breach produces no headline number at all.
6. **Report completeness.** The published result card must carry: raw-order win-rate, swap-collapsed win-rate, length-controlled win-rate, order-flip rate, slot-A rate (with CI), and `beta_len` (with CI). A result card missing any of these fields is rejected in review.
7. **Independence from downstream aggregation.** The Bradley-Terry fit from [exercise-04](../exercise-04-bradley-terry-arena-implementation/SOLUTION.md) must consume the **swap-collapsed** pairs, not the raw per-order judgements. Validate with a fixture: a judge with a strong slot-A preference should produce a different BT skill ordering from raw per-order data than from swap-collapsed data.

### 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Every pair is judged in both orderings with identical judge config | 2 | The runner emits two records per pair; the records share `judge_decoding` and `order_seed`. |
| R2 | Swap-collapse rule is explicit, committed, and unit-tested | 2 | The 9-cell truth table is codified; a direct contradiction (xy→x, yx→y) is counted as tie *and* flagged. |
| R3 | Slot-A rate and order-flip rate are computed per run and surfaced | 1 | Audit JSON ships with every result card; the CI for slot-A rate is reported, not just the point estimate. |
| R4 | Length-bias audit is run and a length-controlled win-rate is published alongside the raw one | 1 | `beta_len` with CI; a length-controlled win-rate is on the result card. |
| R5 | Publication gates are committed as thresholds, not inline literals | 1 | `thresholds.yaml` governs warn/block decisions; changes require a code review, not a config diff. |
| R6 | Length-matching at generation time is attempted first | 1 | Candidates are generated with the same budget, or pairs are filtered to a committed length-ratio cap. |
| R7 | Tie fraction and per-criterion winners are preserved in the per-item record | 1 | A reviewer can replay any single verdict and see what criterion drove it. |
| R8 | Result card labels the half-credit-for-ties convention and the collapse rule | 1 | The card explains how 60% was computed; nothing is left to a reader's convention. |

**Passing bar:** 7 / 10.

Reviewer checklist:

- [ ] Swap orderings share the judge seed; only slot assignment differs.
- [ ] `collapse()` is unit-tested against the full 3×3 verdict matrix.
- [ ] `thresholds.yaml` is source-controlled; threshold changes are reviewed.
- [ ] Length-controlled win-rate is on the headline result card, not buried in an appendix.
- [ ] `beta_len` CI is reported and the sample size is big enough that the CI is useful (> 300 pairs for narrow bands).
- [ ] The Bradley-Terry fit downstream consumes collapsed pairs, not raw per-order judgements.
- [ ] A fresh run reproduces all audit numbers given the same seed.

### 5. Common mistakes

- **Reporting the raw-order win-rate as the headline.** Without the swap-collapse, a 2-point slot-A bias moves the published number by 2 points for no content reason.
- **Averaging verdicts across orderings as 0.5/0.5.** Order-flip pairs are not "half a win for each side"; they are evidence that the judge is noisy on this pair. The right action is to tie them and count the flip rate.
- **Fitting length bias on winner-only pairs.** Dropping ties is correct; dropping losses is not. The regression must see both outcomes or `beta_len` is biased by construction.
- **Using `beta_len` significance as a gate.** With enough pairs any non-zero bias is "significant." The right gate is effect size (`|beta_len|`), not a p-value.
- **Length-matching after generation only.** If the generator is already emitting a 2× length ratio, filtering at the pair layer throws out half the data. Match at generation time; filter only as a backstop.
- **Half-credit-for-ties without saying so.** The arena convention differs from the "ignore ties" convention; a reader who assumes the other one reads 0.55 as a comfortable win when it is a tie-heavy near-wash.
- **Running both orderings with different seeds.** If the two judgements have different judge RNG state, the slot-A rate is confounded with sampling noise and the audit becomes uninterpretable.
- **Measuring bias once and never again.** Judges drift as models update. The audit runs *every time* a result card is produced, not once at setup.

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires measurements to be reliable under non-material perturbations; position-swap and length-matching are the concrete controls that keep the LLM-as-judge win-rate reliable under slot and length perturbations.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML01 Input Manipulation** is the direct mapping — length-bias is a free attack vector for a response generator that knows the judge is verbose-biased.
- MITRE ATLAS — <https://atlas.mitre.org/>. `LLM Prompt Injection` and `Craft Adversarial Data` cover the attacker tactics the controls defend against.

<!-- Local exercise context: the specific thresholds in `thresholds.yaml` (0.10 flip-rate, 0.40/0.60 slot-A block band, 0.35 beta_abs_block) are illustrative starting points. Re-derive them against your own calibration data in exercise-03 before promoting to production. -->
