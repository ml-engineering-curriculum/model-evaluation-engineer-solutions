## exercise-05 — Judge Tier Routing and Cost Model — Solution

### 1. Solution overview

Running the most capable judge on every item is rarely the right policy. A cheap judge handles the easy majority; an expensive judge handles the items the cheap judge cannot score confidently. The exercise asks the learner to design a **two-tier routing policy with a committed cost model**: decide which items the cheap judge can resolve, which items escalate, and what the expected spend / accuracy tradeoff looks like.

The reference answer has five deliverables:

1. A **judge-tier catalogue** — committed configs for the cheap and expensive judges, pinned by model, revision, prompt version, and decoding.
2. A **routing policy** — the rule that decides whether to accept the cheap verdict or escalate to the expensive judge, grounded in the cheap judge's calibrated confidence from [exercise-03](../exercise-03-judge-vs-human-calibration-study/SOLUTION.md).
3. A **cost model** — $/judgement for each tier, expected calls per item under the policy, and a projected total cost with a sensitivity band.
4. A **budget-constrained variant** — a policy that routes the N most-informative items to the expensive judge subject to a fixed total budget, used when the cheap judge's confidence is itself unreliable.
5. A **monitoring layer** — escalation rate, drift alerts, and a kill-switch that falls back to all-expensive when the cheap judge disagrees with the expensive judge above a committed threshold on sampled traffic.

The adversarial lens is OWASP ML Top 10 **ML01 Input Manipulation** — an attacker who knows the cheap judge is lenient on long responses can route around the expensive judge by producing items that the cheap tier accepts with high confidence ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). NIST AI RMF `MEASURE` requires the routing policy to be documented and bounded by committed thresholds, not inferred from behavior at runtime ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). MITRE ATLAS `Evade ML Model` captures the attacker who deliberately stays inside the cheap tier's acceptance region to avoid a higher-fidelity judge ([MITRE ATLAS](https://atlas.mitre.org/)).

### 2. Worked implementation

#### 2.1 Judge-tier catalogue

Pin everything. A judge-tier catalogue that leaves the prompt or decoding floating is one that silently rerates history.

```yaml
# judges/catalogue.yaml
tiers:
  cheap:
    id: judge_cheap_v1
    model: "<org>/<small-model>"
    revision: "<sha>"
    decoding: {temperature: 0.0, top_p: 1.0, seed: 1234}
    prompt_version: "judge_pairwise.prompt.j2@<sha>"
    cost_per_judgement_usd: 0.0008    # from the provider's committed price card; audited monthly
    p50_latency_ms: 420
    calibration_study_id: judge_calibration_helpfulness_v1_cheap

  expensive:
    id: judge_expensive_v1
    model: "<org>/<large-model>"
    revision: "<sha>"
    decoding: {temperature: 0.0, top_p: 1.0, seed: 1234}
    prompt_version: "judge_pairwise.prompt.j2@<sha>"
    cost_per_judgement_usd: 0.0175
    p50_latency_ms: 2900
    calibration_study_id: judge_calibration_helpfulness_v1_expensive
```

Rules:

- **Both tiers have a calibration study id.** Routing is only defensible when you know each tier's agreement with humans (see [exercise-03](../exercise-03-judge-vs-human-calibration-study/SOLUTION.md)). A cheap judge with unknown kappa is not a tier, it is a guess.
- **Prompts are the same shape across tiers.** The schema from [exercise-01](../exercise-01-absolute-and-pairwise-rubric-design/SOLUTION.md) is identical; only the model behind the prompt differs. Changing the prompt per tier makes the escalation outputs non-comparable.
- **Cost is the provider's price card value.** Do not guess. Audit the price card monthly — a silent price change from the provider is an uncaptured spend risk.

#### 2.2 Routing policy: confidence-gated escalation

Each cheap judgement comes with a *calibrated* confidence. For a pairwise verdict, the natural confidence is the cheap judge's agreement rate with humans on **items that look like this one** — specifically, the per-stratum kappa from the exercise-03 calibration study. For an absolute judgement, the natural confidence is a residual-magnitude bound.

The simplest and most defensible calibrated confidence for pairwise mode uses the cheap judge's **per-criterion winner vote**:

- `strong_cheap`: all per-criterion winners agree with the overall verdict, and the per-criterion evidence is non-empty for every criterion.
- `weak_cheap`: per-criterion winners disagree with the overall verdict, OR any criterion has empty evidence, OR the verdict is a "tie" that was adjudicated by the aggregation threshold rather than a per-criterion agreement.

```python
# routing/confidence.py
from pairwise_controls.swap import SwapCollapsed


def cheap_confidence(swap: SwapCollapsed, cheap_raw_xy: dict, cheap_raw_yx: dict) -> str:
    """Return 'strong' | 'weak' based on the cheap judge's self-consistency.

    The cheap judge is already swap-collapsed. We call it 'strong' only when
    both orderings agreed and every per-criterion winner lines up with the
    overall verdict.
    """
    # Inconsistent across swap orderings -> weak by construction.
    if swap.inconsistency:
        return "weak"

    def per_criterion_ok(raw: dict, overall: str) -> bool:
        per = raw.get("per_criterion", {})
        for c in per.values():
            if not c.get("evidence"):
                return False
            if c["winner"] not in {overall, "tie"}:
                return False
        return True

    overall = {"xy": "A", "yx": "B"}.get(cheap_raw_xy.get("verdict", ""), cheap_raw_xy.get("verdict", ""))
    ok_xy = per_criterion_ok(cheap_raw_xy, cheap_raw_xy["verdict"])
    ok_yx = per_criterion_ok(cheap_raw_yx, cheap_raw_yx["verdict"])
    return "strong" if (ok_xy and ok_yx) else "weak"
```

The routing rule:

```yaml
# routing/policy.yaml
policy_id: two_tier_v1
mode: pairwise
rules:
  - when: "cheap_confidence == 'strong' AND cheap_verdict != 'tie'"
    action: "accept_cheap"
  - when: "cheap_confidence == 'strong' AND cheap_verdict == 'tie'"
    action: "escalate"               # ties are the highest-value escalation
  - when: "cheap_confidence == 'weak'"
    action: "escalate"
reconcile:
  on_disagreement: "use_expensive"   # if cheap accept is later found to disagree with expensive on sampled items, log and keep expensive
```

Routing choices worth naming:

- **Accept-cheap only on strong-and-decisive.** A `strong` tie is worth escalating: ties are where the arena-level signal is thinnest (see [exercise-04](../exercise-04-bradley-terry-arena-implementation/SOLUTION.md)), and the cost of breaking a tie correctly is high relative to the cost of the expensive call.
- **Never accept-cheap on inconsistency.** A pair where the two swap orderings disagreed is noise; accepting it on the cheap tier is accepting noise.
- **`reconcile.on_disagreement = use_expensive`.** The expensive judge is the reference. If a sampled reconciliation reveals a disagreement, the expensive verdict is the record; the cheap verdict is kept in the forensics file but not published.

#### 2.3 Cost model

With a routing policy, the per-item expected cost is a weighted mix of the two tiers. Let:

- $p_s$ = fraction of items the cheap judge calls `strong` and *not* a tie (accept rate)
- $p_e = 1 - p_s$ = escalation rate
- $c_c, c_e$ = per-judgement cost of cheap and expensive tiers
- Every item incurs the cheap cost; escalated items incur the expensive cost on top.

$$
\mathbb{E}[\text{cost per item}] = c_c + p_e \cdot c_e
$$

With illustrative numbers from `catalogue.yaml` and a strong-rate of 70% (from a pilot), expected per-item cost is $0.0008 + 0.30 \cdot 0.0175 = \$0.00605$. The all-expensive baseline is $0.0175 per item; routing saves $(0.0175 - 0.00605) / 0.0175 \approx 65\%$ of the spend.

Report the cost model as a committed table, with a sensitivity band on $p_s$:

```python
# routing/cost_model.py
from dataclasses import dataclass


@dataclass(frozen=True)
class CostInputs:
    c_cheap: float
    c_expensive: float
    strong_rate: float
    strong_rate_lo: float
    strong_rate_hi: float
    sample_size: int


def expected_cost_per_item(ci: CostInputs) -> dict:
    def mix(ps):
        pe = 1.0 - ps
        return ci.c_cheap + pe * ci.c_expensive

    return {
        "expected_per_item": mix(ci.strong_rate),
        "band_lo": mix(ci.strong_rate_hi),  # higher strong rate -> lower cost
        "band_hi": mix(ci.strong_rate_lo),
        "baseline_all_expensive": ci.c_expensive,
        "savings_fraction_vs_baseline": 1.0 - mix(ci.strong_rate) / ci.c_expensive,
        "sample_size": ci.sample_size,
    }
```

Put the Wilson-score CI on `strong_rate` from the pilot into `strong_rate_lo` / `strong_rate_hi`. A cost estimate without a sensitivity band is a wish.

#### 2.4 Budget-constrained variant

When the cheap judge's calibrated confidence is not yet trusted (new rubric, new cheap model, new domain), route by *information value* instead. Given a fixed budget `B` dollars, pick the `B / c_e` items that are most likely to be mis-ruled by the cheap judge:

- For pairwise mode, the natural information-value proxy is **1 - |cheap_overall_score_margin|**, i.e., items the cheap judge rates as closest to a tie. These are the items where the cheap verdict is least reliable and where an expensive verdict changes downstream aggregation the most.
- For absolute mode, the natural proxy is the **distance from the publication threshold**. If the headline is "fraction of items with score >= 4.0," the items near the 4.0 boundary are the ones where a flip matters.

```python
# routing/budget_routing.py
from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    item_id: str
    cheap_margin: float  # for pairwise: closer to 0 = closer to tie
    cheap_cost: float
    expensive_cost: float


def pick_within_budget(candidates: list[Candidate], total_budget_usd: float) -> list[str]:
    """Greedy selection by ascending margin (most informative first) under a hard budget cap.
    Returns the list of item_ids chosen for expensive judging.
    """
    ordered = sorted(candidates, key=lambda c: abs(c.cheap_margin))
    chosen = []
    spent = sum(c.cheap_cost for c in candidates)  # cheap runs on everything first
    for c in ordered:
        if spent + c.expensive_cost > total_budget_usd:
            break
        chosen.append(c.item_id)
        spent += c.expensive_cost
    return chosen
```

Report the knee of the information-value curve: fraction of ambiguous items escalated vs budget consumed. The knee is where incremental spend stops moving the headline; publishing that curve is the honest version of "we picked a budget."

#### 2.5 Monitoring and kill-switch

Routing is a live policy, not a one-time decision. Two monitors run continuously:

- **Escalation rate** — the fraction of items escalated. A sudden drop ("cheap judge suddenly thinks everything is strong") or spike ("cheap judge suddenly disagrees with itself") is a drift signal. Alert at ±20% relative drift over a 7-day rolling window.
- **Sampled reconciliation** — a randomly selected 5% of accept-cheap items are also judged by the expensive judge. The disagreement rate on this sample is the empirical cost of the cheap tier. When it crosses a committed threshold, flip the kill-switch:

```yaml
# routing/kill_switch.yaml
reconcile:
  sample_rate: 0.05
  window_items: 2000
  kill_switch:
    disagreement_rate_threshold: 0.12   # fall back to all-expensive above this
    hysteresis_floor: 0.08              # re-enable cheap tier below this
    action: "route_all_to_expensive"
    alert_channel: "evals-oncall"
```

Hysteresis matters. A single bad window should not flip the switch; a single good window should not flip it back. The hysteresis band is a pre-commitment.

### 3. Validation steps

1. **Catalogue pinning check.** A script loads `judges/catalogue.yaml` and asserts that every tier has model, revision, prompt_version, decoding seed, cost, and calibration_study_id. A missing field fails the build — not a warning.
2. **Pilot with ground truth.** On the same 150-item calibration set from [exercise-03](../exercise-03-judge-vs-human-calibration-study/SOLUTION.md), run both tiers and the routing policy. Report: cheap-accept accuracy vs humans, escalate-then-expensive accuracy vs humans, blended accuracy, actual cost. Blended accuracy must be within a committed ε of the all-expensive accuracy (e.g., ε = 2 percentage points); if not, the routing policy is losing quality and must be re-tuned.
3. **Confidence sanity.** Confirm that `strong` items have higher cheap-vs-expensive agreement than `weak` items on a held-out set. If they don't, the confidence function is uninformative and the policy degenerates to random routing.
4. **Budget-model back-test.** Replay a month of historical pair records through the routing policy and compute the realized cost. Compare to the committed cost model. A gap > 15% means `strong_rate` was mis-estimated — retune the pilot.
5. **Reconcile loop smoke test.** Inject 5 known-disagreement pairs into traffic and confirm the monitor records them, the disagreement rate crosses the threshold in the test window, and the kill-switch fires in a staging environment. The kill-switch is the one piece of code that must be exercised, not just reviewed.
6. **Position-bias passthrough.** The routing policy must consume swap-collapsed pairs (see [exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md)). Running the policy on raw per-order pairs silently inflates escalation rate; add an assertion that batches are collapsed before they enter `routing/run.py`.
7. **Dollar reconciliation.** Monthly: compare the provider's actual invoice to `sum(c_tier * calls_tier)` from the routing log. A gap is either a price-card change (update `catalogue.yaml`) or missing calls in the log (fix the log). Either way, do not ship a cost model you cannot reconcile to invoices.

### 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Tier catalogue pins model, revision, prompt, decoding, cost, calibration study | 2 | `judges/catalogue.yaml` has every field; a missing field fails the build. |
| R2 | Routing policy is committed as a YAML rule, not inline code | 1 | `routing/policy.yaml` names the rule conditions; code reads the YAML, does not re-derive the rules. |
| R3 | Cheap-confidence function is explicit, deterministic, and testable | 1 | `cheap_confidence` has unit tests for the strong / weak decision; a `weak` item never gets accept-cheap. |
| R4 | Cost model has a sensitivity band on `strong_rate` | 1 | `expected_cost_per_item` reports a band derived from the pilot's Wilson CI; the result card shows both point and band. |
| R5 | Blended-accuracy-vs-cost tradeoff is published | 2 | Pilot numbers on a committed held-out set; blended accuracy within committed ε of all-expensive. |
| R6 | Reconciliation sampling and kill-switch are implemented and alarmed | 1 | `kill_switch.yaml` + a staging test that fires the switch end-to-end. |
| R7 | Budget-constrained variant handles the cold-start case | 1 | When the cheap confidence is untrusted, information-value routing picks items near the decision boundary; the knee curve is reported. |
| R8 | Dollar reconciliation to invoices is a committed monthly task | 1 | Runbook names the owner, the cadence, and the action when invoice ≠ logged cost. |

**Passing bar:** 7 / 10.

Reviewer checklist:

- [ ] Both tiers have a calibration study id from [exercise-03](../exercise-03-judge-vs-human-calibration-study/SOLUTION.md); neither is uncalibrated.
- [ ] Prompts are identical in shape across tiers; only the model differs.
- [ ] Routing policy is a YAML rule file; code is thin.
- [ ] Cost model's `strong_rate` CI is the Wilson CI from the pilot sample size, not a point estimate.
- [ ] Blended accuracy is reported on a held-out set, not the pilot used to tune `strong_rate`.
- [ ] Reconcile sampling is wired to a monitor with a committed alert owner.
- [ ] Kill-switch uses hysteresis; a single bad window does not trip it.
- [ ] Monthly invoice reconciliation is a runbook step, not a hope.

### 5. Common mistakes

- **Routing by provider price alone.** The cheap judge is only "cheap" if its blended accuracy matches the quality bar; otherwise you are buying wrong answers at a discount.
- **Confidence from the judge's own self-reported certainty.** LLMs are miscalibrated self-raters by default. Build confidence from structural signals (per-criterion agreement, swap consistency, margin), not "how confident are you (1-10)?" tokens.
- **Changing the prompt per tier.** A cheap-tier prompt that omits criteria the expensive-tier prompt includes makes the escalation outputs incomparable; downstream aggregation is corrupted silently.
- **Accepting cheap ties.** Ties are where the aggregate signal is thinnest; they are the highest-value escalation. Accepting them on the cheap tier is the single most common way routing loses quality.
- **No reconciliation sampling.** A routing policy without a live comparison to the expensive judge decays as traffic patterns drift; by the time someone notices, you have months of corrupted headline numbers.
- **Kill-switch with no hysteresis.** A single noisy window flips the switch, the next window flips it back, and the system is unstable at the worst possible time.
- **Cost model that drops provider-side price changes.** Provider prices change; a cost model with a hard-coded number diverges from reality. Monthly invoice reconciliation is the forcing function.
- **Blended-accuracy measured on the same set used to tune the policy.** Hold out a fresh set; the pilot set is burned the moment you tune `strong_rate` against it.

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires the routing policy and its cost / quality tradeoff to be documented and tied to an operational context — not implicit in code behavior.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML01 Input Manipulation** names the risk that an attacker crafts responses that stay inside the cheap tier's acceptance region to avoid higher-fidelity review; reconciliation sampling is the defense.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Evade ML Model` captures the attacker who optimizes for the cheap judge's bias; the kill-switch and hysteresis are the operational response.

<!-- Local exercise context: the specific per-judgement costs ($0.0008 and $0.0175), the strong_rate of 70%, and the kill-switch thresholds are illustrative numbers. Reproduce them from your own pilot + provider price card before publishing a cost model; the one non-negotiable is that both tiers have a calibration study from exercise-03. -->
