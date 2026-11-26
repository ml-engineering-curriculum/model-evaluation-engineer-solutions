# exercise-03 — Platform Cost Controls — Solution

## 1. Solution overview

An eval platform without cost controls is a platform that discovers, on the finance team's monthly review, that a stale cron job spent $18,000 scoring the same 2,000 items through a top-tier hosted judge for six weeks. The failure mode is specific: eval workloads look cheap per-item, grow 50× when someone adds a judge, repeat on cron, and are charged to a shared account where the per-service attribution is "platform." The controls are not a dashboard; they are **pre-flight budgets, mid-flight quotas, and after-the-fact chargeback** that together make the cost of a run a design decision the submitter can see before they click.

The design hinges on four non-negotiables:

- **Cost estimation before submit, not after completion.** Every `RunSpec` is estimated — tokens × model price, judge calls × judge price, GPU-seconds × pool rate, human-rater items × vendor rate — and the estimate is shown to the submitter before the run is accepted. An estimate that exceeds the caller's quota is rejected at submit time, not at hour three.
- **Quotas are per (team, environment, backend).** The platform budget is not one bucket. The judge-model budget is separate from the GPU-pool budget; `prod` is separate from `dev`; team A's spend does not starve team B.
- **Hard caps and soft caps.** A hard cap kills a run that exceeds it. A soft cap pauses and pages an owner. Both are per-run and per-period (daily, monthly). A hard cap without a soft cap is a blameless surprise; a soft cap without a hard cap is advice that will be ignored.
- **Chargeback that names the caller, not the platform.** Every cost row has `team`, `cost_center`, `run_id`, `shard_id`, and `backend`. The platform does not absorb; it accounts and bills back. Finance can run `SELECT team, SUM(dollars)` and get a correct number.

The reference answer has five deliverables:

1. A **cost model** (`pricing.yaml`) — the committed, versioned price table per backend, with per-unit rates and the formula that maps from backend units (tokens, seconds, items) to dollars.
2. An **estimator** (`estimator.py`) that returns a dollar estimate with a CI for any `RunSpec` before submit.
3. A **quota and budget service** (`budgets.py`) with team/env/backend buckets, enforcement at submit and at every shard submit, and committed caps.
4. A **chargeback and attribution model** (`chargeback.sql`) that joins per-shard cost rows with teams and cost centers and produces per-period attribution.
5. A **policy doc** (`docs/cost-policy.md`) describing hard-vs-soft caps, approvals for cap raises, and the FinOps review cadence.

This maps directly to the NIST AI RMF `GOVERN` and `MANAGE` functions: `GOVERN` asks for "resource allocation and accountability structures documented and operationalized"; a per-team budget enforced by the submit path is the operationalization. `MANAGE` asks for "risk prioritization reflected in resource decisions" — hard caps on hosted-judge spend and soft caps on GPU-pool spend reflect the organization's actual risk appetite ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML04 Model Denial of Service** (an uncapped eval becomes a cost-DoS; a hostile prompt pattern that drives up output tokens is an economic attack on the budget — a gate without a cap is a check without a lock) and **ML06 AI Supply Chain Attacks** (a judge publish that changed the backbone silently and doubled per-call cost is a supply-chain cost regression; the estimator's per-backend price pin catches the delta pre-submit) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0029 Denial of ML Service` is specifically the attack a cost cap defends against: the organization's own repeated, uncapped runs can degrade a shared backend's cost posture as effectively as an external DoS ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked design and implementation

### 2.1 Pricing config

```yaml
# pricing.yaml  (versioned in the registry; see exercise-01)
schema_version: 1
effective_from: 2026-11-01T00:00:00Z
backends:
  - name: internal-judge-llm
    kind: api-llm
    units:
      input_tokens_per_dollar: 1_250_000     # $0.80 / M input tokens
      output_tokens_per_dollar:   250_000    # $4.00 / M output tokens
    minimum_billable_tokens: 1
    source: vendor-contract-2026-10

  - name: external-judge-gpt-x
    kind: api-llm
    units:
      input_tokens_per_dollar:   400_000
      output_tokens_per_dollar:   80_000
    minimum_billable_tokens: 1
    source: vendor-public-price-list-2026-10

  - name: gpu-pool-h100-eval-prod
    kind: gpu-pool
    units:
      dollars_per_gpu_second: 0.00111        # ≈ $4.00/h effective
    overhead_seconds_per_shard: 8            # cold-load tokenizer+weights amortized
    source: platform-infra-chargeback-2026-Q4

  - name: cpu-pool-standard
    kind: cpu-pool
    units:
      dollars_per_vcpu_second: 0.000011
    source: platform-infra-chargeback-2026-Q4

  - name: vendor-human-raters
    kind: vendor-human
    units:
      dollars_per_rated_item: 0.35
      dollars_per_rejected_item: 0.05
    source: vendor-contract-2026-Q3

margins:
  platform_overhead_pct: 5.0                 # applied once at chargeback
  estimation_safety_pct: 10.0                # added to the point estimate for caps
```

Rules the pricing config enforces:

- **Pricing is a registry artifact.** A change bumps a new version and is approved like any other config change. "We renegotiated the judge price and forgot to update the config" is why a run came in 2× over estimate.
- **Every unit has a source citation.** Where the number came from is a column, not a comment. Finance can audit the whole table in one query.
- **`estimation_safety_pct` is explicit.** The estimator reports a point and a padded value; the quota check uses the padded value. A quota passed on the point but exceeded by the actual is the single most common failure mode.

### 2.2 Estimator

```python
"""Pre-flight cost estimator. Produces (point, high_bound) in dollars.

The estimator is called twice:
  - once at submit, to gate against the caller's quota,
  - once per shard replan, so a budget-paused run can be partially released."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Estimate:
    point_dollars: float
    high_dollars: float          # point + estimation_safety_pct
    by_backend: dict[str, float] # backend_name -> point dollars


class Estimator:
    def __init__(self, pricing, dataset_catalog, judge_catalog) -> None:
        self._p = pricing
        self._datasets = dataset_catalog
        self._judges = judge_catalog

    def estimate(self, spec) -> Estimate:
        total = 0.0
        by_backend = {}

        n_items = self._datasets.length(spec.dataset)
        for runner in spec.runners:
            if runner["kind"] == "api-llm":
                d = self._api_llm_cost(runner, n_items, spec)
            elif runner["kind"] == "gpu-pool":
                d = self._gpu_cost(runner, n_items, spec)
            elif runner["kind"] == "cpu-pool":
                d = self._cpu_cost(runner, n_items, spec)
            elif runner["kind"] == "vendor-human":
                d = self._human_cost(runner, n_items, spec)
            else:
                raise ValueError(f"no price model for {runner['kind']}")
            by_backend[runner["name"]] = d
            total += d

        # Each declared judge is a second pass over the items at the judge's
        # backend. A run that lists 2 judges pays twice.
        for judge_uri in spec.judges:
            j = self._judges.resolve(judge_uri)
            d = self._judge_cost(j, n_items)
            by_backend[f"judge:{j.name}"] = d
            total += d

        safety = self._p.margins["estimation_safety_pct"] / 100.0
        return Estimate(
            point_dollars=total,
            high_dollars=total * (1.0 + safety),
            by_backend=by_backend,
        )

    def _api_llm_cost(self, runner, n_items, spec):
        """Estimate = n_items × (avg_input_tokens / input_rate + avg_output_tokens / output_rate).

        avg_input_tokens and avg_output_tokens come from either a profile row
        (prior runs of this dataset × this model) or a conservative default
        from the dataset's metadata. A run against a dataset with no profile
        uses the default and raises a WARN; the estimate is less trustworthy."""
        prof = self._datasets.profile(spec.dataset, runner["provider"])
        inp = prof.avg_input_tokens if prof else self._datasets.default_input_tokens(spec.dataset)
        out = prof.avg_output_tokens if prof else self._datasets.default_output_tokens(spec.dataset)
        price = self._p.backends[runner["provider"]].units
        return n_items * (inp / price["input_tokens_per_dollar"] + out / price["output_tokens_per_dollar"])

    def _gpu_cost(self, runner, n_items, spec):
        """Estimate = (n_items / throughput_items_per_second + overhead) × price_per_gpu_second × concurrency.

        throughput_items_per_second comes from the pool's profile for this
        (model, pool, selectors) tuple; a cold model profile uses a default
        with a WARN."""
        prof = self._datasets.throughput(spec.model, runner["selectors"])
        rate = prof.items_per_second if prof else 1.0
        price = self._p.backends[self._p.pool_name(runner)].units
        secs_per_shard = (spec.shard_strategy["shard_size"] / rate) + self._p.backends[self._p.pool_name(runner)]["overhead_seconds_per_shard"]
        n_shards = math.ceil(n_items / spec.shard_strategy["shard_size"])
        return n_shards * secs_per_shard * price["dollars_per_gpu_second"]

    # _cpu_cost, _human_cost, _judge_cost: analogous
```

Rules the estimator enforces:

- **Profiles are measured, not guessed.** `avg_input_tokens` for a dataset × model pair is a row written by prior runs' completion hooks; the estimator reads it. A missing profile is a WARN on the submit response.
- **Multiple judges multiply cost.** A `RunSpec` that lists two judges pays two judge passes. The estimator makes that visible per-judge in `by_backend` so the submitter can see "Judge A: $40, Judge B: $40 — do you need both?"
- **The high bound is what the quota checks against.** Checking against the point estimate guarantees overshoots; the safety margin is the cushion the platform promises its finance team.

### 2.3 Quota and budget service

```python
"""Budgets, quotas, and enforcement.

Three bucket dimensions: team × environment × backend. Each bucket has a
daily cap and a monthly cap; each cap has a hard limit and a soft limit."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class BucketKey:
    team: str                      # "model-eval", "product-nlp", ...
    environment: str               # "dev" | "staging" | "prod"
    backend: str                   # "internal-judge-llm", "gpu-pool-h100-eval-prod", ...


@dataclass
class BucketCaps:
    daily_soft: float
    daily_hard: float
    monthly_soft: float
    monthly_hard: float


class BudgetService:
    def __init__(self, caps_store, usage_store, notifier) -> None:
        self._caps = caps_store
        self._usage = usage_store
        self._notify = notifier

    def check_submit(self, spec, estimate) -> "SubmitDecision":
        """Called at run-submit time. Rejects a run whose estimate would push
        any bucket over its daily or monthly hard cap. Warns (but accepts) on
        soft-cap overshoot."""
        warnings = []
        for backend_name, dollars in estimate.by_backend.items():
            key = BucketKey(spec.team, spec.environment, backend_name)
            caps = self._caps.get(key)
            usage = self._usage.current(key)
            if usage.daily + dollars > caps.daily_hard:
                return SubmitDecision("reject", f"daily hard cap exceeded on {backend_name}: "
                    f"{usage.daily:.2f} + {dollars:.2f} > {caps.daily_hard:.2f}")
            if usage.monthly + dollars > caps.monthly_hard:
                return SubmitDecision("reject", f"monthly hard cap exceeded on {backend_name}")
            if usage.daily + dollars > caps.daily_soft:
                warnings.append(f"daily soft cap on {backend_name}: "
                    f"{usage.daily + dollars:.2f} > {caps.daily_soft:.2f}")
            if usage.monthly + dollars > caps.monthly_soft:
                warnings.append(f"monthly soft cap on {backend_name}")
        return SubmitDecision("accept", "ok", warnings=warnings)

    def has_headroom(self, run_id, budget) -> bool:
        """Called by the orchestrator before every shard submit. Returns
        False if the run's cumulative actual spend would push a bucket over
        a hard cap in the next shard; the orchestrator pauses."""
        run = self._usage.run(run_id)
        projected = run.actual_dollars + run.avg_cost_per_shard
        if projected > budget.max_dollars:
            return False
        for key in self._usage.buckets_for(run_id):
            caps = self._caps.get(key)
            if self._usage.current(key).daily + run.avg_cost_per_shard > caps.daily_hard:
                return False
        return True

    def record(self, run_id, shard_id, backend, dollars) -> None:
        self._usage.append(run_id, shard_id, backend, dollars, when=_now())
        self._maybe_notify_soft_breach(run_id, backend)


@dataclass
class SubmitDecision:
    verdict: str                    # "accept" | "reject"
    reason: str
    warnings: list[str] | None = None
```

Rules the service enforces:

- **`check_submit` is the hard gate at submit time.** A run that cannot fit under any bucket's hard cap is rejected at submit; the caller does not spend a second on a run that will be killed.
- **`has_headroom` is called before every shard submit.** The orchestrator pauses on `False`; it does not cancel. An on-call engineer can raise the cap (audited) or cancel the run.
- **Soft breaches notify but do not block.** A page to the team owner on a soft breach is the lever that gets caps raised intentionally, not when a run has already died.
- **`record` is idempotent on `(run_id, shard_id, backend)`.** A replayed completion hook does not double-charge.

### 2.4 Caps storage

```sql
CREATE TABLE bucket_caps (
    team            TEXT NOT NULL,
    environment     TEXT NOT NULL,
    backend         TEXT NOT NULL,
    daily_soft      NUMERIC NOT NULL,
    daily_hard      NUMERIC NOT NULL,
    monthly_soft    NUMERIC NOT NULL,
    monthly_hard    NUMERIC NOT NULL,
    effective_from  TIMESTAMPTZ NOT NULL,
    set_by          TEXT NOT NULL,
    PRIMARY KEY (team, environment, backend, effective_from)
);

CREATE TABLE cap_change_requests (
    id              BIGSERIAL PRIMARY KEY,
    team            TEXT NOT NULL,
    environment     TEXT NOT NULL,
    backend         TEXT NOT NULL,
    field           TEXT NOT NULL,    -- "daily_hard", etc
    old_value       NUMERIC NOT NULL,
    new_value       NUMERIC NOT NULL,
    reason          TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    approved_by     TEXT,
    requested_at    TIMESTAMPTZ NOT NULL,
    approved_at     TIMESTAMPTZ,
    CHECK (new_value >= 0)
);

CREATE TABLE cost_rows (
    id              BIGSERIAL PRIMARY KEY,
    run_id          TEXT NOT NULL,
    shard_id        TEXT NOT NULL,
    backend         TEXT NOT NULL,
    team            TEXT NOT NULL,
    environment     TEXT NOT NULL,
    cost_center     TEXT NOT NULL,
    dollars         NUMERIC NOT NULL,
    units           NUMERIC NOT NULL,       -- tokens, seconds, items (keyed by backend.kind)
    unit_kind       TEXT NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    pricing_sha     TEXT NOT NULL,          -- which pricing.yaml was effective
    UNIQUE (run_id, shard_id, backend)      -- idempotent record
);
```

Rules the schema enforces:

- **`bucket_caps` is effective-dated, not mutated.** A cap raise is a new row; the old row remains for audit. A monthly review that asks "what was the limit on 2026-10-01?" has a single-row answer.
- **Every cap change is a request + approval.** A unilateral raise is a cultural failure, not a technical one; the schema makes the request/approve flow table-level visible.
- **`cost_rows` pins the pricing SHA.** The same backend's price changed on 2026-11-01; cost rows from 2026-10 are evaluated with 2026-10 prices. Chargeback is reconstructable.

### 2.5 Chargeback

```sql
-- Monthly chargeback report. One row per (team, cost_center, backend) per month.
SELECT
    date_trunc('month', occurred_at) AS month,
    team,
    cost_center,
    backend,
    SUM(dollars)                     AS dollars,
    SUM(units)                       AS units,
    COUNT(DISTINCT run_id)           AS n_runs,
    COUNT(DISTINCT shard_id)         AS n_shards
FROM cost_rows
WHERE occurred_at >= :month_start AND occurred_at < :month_end
GROUP BY 1, 2, 3, 4
ORDER BY dollars DESC;

-- Attribution across environments: catches "dev is spending prod money"
SELECT
    team,
    environment,
    SUM(dollars) AS dollars
FROM cost_rows
WHERE occurred_at >= :month_start AND occurred_at < :month_end
GROUP BY team, environment
ORDER BY team, dollars DESC;

-- Top-N expensive runs: for FinOps review
SELECT
    run_id,
    team,
    environment,
    SUM(dollars) AS run_dollars,
    (array_agg(DISTINCT backend)) AS backends_used,
    MIN(occurred_at) AS started_at,
    MAX(occurred_at) AS last_cost_at
FROM cost_rows
WHERE occurred_at >= :month_start AND occurred_at < :month_end
GROUP BY run_id, team, environment
ORDER BY run_dollars DESC
LIMIT 50;
```

Chargeback outputs land in the organization's billing table; finance consumes the per-team totals. The eval platform does not "absorb" costs — the platform's own operational cost (orchestrator CPU, databases) is amortized across teams by a per-run overhead charge driven by `margins.platform_overhead_pct`.

### 2.6 Submit path

```python
"""End-to-end submit wiring.

Steps:
  1. Validate the spec (schema).
  2. Resolve every artifact URI via the registry (see exercise-01). A deprecated
     URI is a WARN; a sunset URI is a REJECT.
  3. Estimate the run cost.
  4. check_submit() against the caller's team × env × backend quotas.
  5. On accept, write runs row, write shards, enqueue first tick.
  6. On reject, return the reason + the specific bucket that failed."""

def submit(spec, caller) -> SubmitResponse:
    _validate_schema(spec)
    _resolve_all(spec)
    est = estimator.estimate(spec)
    decision = budgets.check_submit(spec, est)
    if decision.verdict == "reject":
        return SubmitResponse(
            accepted=False,
            reason=decision.reason,
            estimate_dollars=est.high_dollars,
            by_backend=est.by_backend,
        )
    run_id = orchestrator.submit_run(spec)
    return SubmitResponse(
        accepted=True,
        run_id=run_id,
        estimate_dollars=est.high_dollars,
        by_backend=est.by_backend,
        warnings=decision.warnings,
    )
```

### 2.7 Policy doc

```markdown
# docs/cost-policy.md (excerpt)

## Caps by environment
- `dev`: team-level default daily hard cap $50; monthly hard $500.
- `staging`: team-level default daily hard $200; monthly hard $2,000.
- `prod`: team-level default daily hard $1,000; monthly hard $10,000.

Values above are the platform defaults; a team-specific override is a row in
`bucket_caps` effective-dated. Judge-model buckets default to half of the
model-serving bucket (judge calls amplify spend ~2×).

## Cap raise process
1. Owner opens a `cap_change_requests` row with: new value, reason, expected
   duration (temporary vs. permanent).
2. Platform FinOps approves within one business day.
3. Approved raise becomes effective from `approved_at`; the old row remains
   in history.

## Hard vs. soft cap behavior
- Soft breach: page to team owner; the run continues. Repeated soft breaches
  within a week trigger a FinOps review of the cap.
- Hard breach at submit: the run is rejected with the offending bucket named.
- Hard breach mid-run: the orchestrator pauses; the owner may raise the cap
  (audited), cancel, or let it time out on the wallclock budget.

## FinOps review cadence
- Weekly: top-20 spenders per team × env × backend.
- Monthly: full chargeback export to finance; reconciliation of estimated vs.
  actual at the per-run level; estimator calibration review (drift > 15%
  triggers a profile rebuild).
```

## 3. Validation steps

1. **Pricing config round-trip.** `pricing.yaml` → load → serialize → equal. Unknown fields fail validation; `effective_from` is required.
2. **Estimator determinism.** Two estimates of the same spec with the same `pricing.yaml` SHA and the same profiles produce byte-identical `Estimate`.
3. **Safety margin applied once.** An estimator test pins `high_dollars == point_dollars * (1 + safety_pct/100)`; adding a judge increases both proportionally.
4. **Submit reject on hard cap.** A synthetic submit whose high-bound exceeds the caller's daily hard cap returns `accepted=False` with the bucket named; `cost_rows` is unchanged; no `runs` row is written.
5. **Submit accept with soft warning.** A submit above soft but below hard returns `accepted=True` with the warning string; the run proceeds; a notification is enqueued.
6. **Orchestrator pause on hard mid-run.** A run that reaches a bucket's hard cap mid-execution transitions to `paused` with `reason='budget_exceeded'`; no further shards submit.
7. **Idempotent `record`.** Two calls to `record(run_id, shard_id, backend, dollars)` produce one `cost_rows` row. A replayed webhook does not double-charge.
8. **Chargeback totals reconcile.** `SUM(cost_rows.dollars)` for a run equals the `dollars_spent` on its `runs` row; a divergence > $0.01 fails CI.
9. **Pricing SHA pinning.** Every `cost_rows` row has a non-null `pricing_sha`; cost from 2026-10 is evaluated with the 2026-10 pricing even after a 2026-11 rate change.
10. **Cap change audit.** Every modification to `bucket_caps` has a corresponding `cap_change_requests` row with `requested_by` and `approved_by`; a cap change without a request is a schema violation enforced by trigger.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards cost being **a pre-flight decision with per-team attribution**, not a finance team's surprise.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Pricing config is a versioned registry artifact with per-backend rates and sources | 1 | `pricing.yaml` pinned by SHA; every rate has a source citation. |
| R2 | Estimator runs at submit and returns (point, high) with per-backend breakdown | 1 | `Estimate` has `point`, `high`, `by_backend`; submit response shows the breakdown. |
| R3 | Multiple judges multiply cost; estimator makes this visible | 1 | Test with two judges returns 2× judge cost in `by_backend`. |
| R4 | Quotas are per (team, environment, backend); hard and soft caps distinct | 2 | `bucket_caps` schema has four thresholds; test covers accept/warn/reject paths. |
| R5 | Submit rejects over hard cap; orchestrator pauses on mid-run hard breach | 1 | Integration test covers both paths. |
| R6 | `record` is idempotent on `(run_id, shard_id, backend)` | 1 | `UNIQUE` constraint; double-record test. |
| R7 | Every `cost_rows` row pins the pricing SHA effective at the time | 1 | Non-null pricing_sha; historical chargeback reproducible. |
| R8 | Chargeback totals reconcile with run-level spent; discrepancy triggers CI failure | 1 | Reconciliation query in CI; fails on > $0.01 divergence. |
| R9 | Cap changes are request + approval, effective-dated | 1 | `cap_change_requests` table; unilateral modification trigger-blocked. |

**Passing bar:** 7 / 10. R2 and R4 are non-negotiable — a cost control system without pre-flight estimation and per-team quotas is a dashboard, not a control.

Reviewer checklist:

- [ ] `pricing.yaml` is a pinned registry artifact; every rate has a source citation.
- [ ] Submit response shows the dollar estimate, high-bound, and per-backend breakdown to the caller.
- [ ] A submit above any hard cap is rejected with the offending bucket named.
- [ ] A submit above soft is accepted with a warning and a notification.
- [ ] Mid-run hard-cap breach pauses; an on-call engineer can resume (audited) or cancel.
- [ ] `cost_rows` has a unique constraint on `(run_id, shard_id, backend)`.
- [ ] Monthly chargeback reconciles to the dollar; divergence > $0.01 fails CI.
- [ ] Every cap change has a request + approval row; no row is created without both.

## 5. Common mistakes

- **Estimating only the model, not the judge.** A $40 judge pass on a $20 model pass doubles cost. The estimator must list each backend separately so the submitter sees "half the bill is the judge."
- **Point estimate as the quota check.** Actuals exceed point estimates roughly half the time by definition. Use the padded high-bound.
- **One global budget.** A team-level budget in the model-eval team's name becomes the budget for the three teams that CC'd `--team=model-eval`. Buckets by team × env × backend.
- **Dev spending as prod.** A dev run that defaults to `environment='prod'` because nobody set the env flag drains the prod budget. Default is `dev`; the submit path refuses `prod` without an explicit approval.
- **Cap stored in a wiki.** The cap and the enforcement must be in the same table. A wiki-only cap is a suggestion.
- **Unilateral cap raises by the team owner.** A cap that can be raised by the person whose run is about to fail is not a cap. Enforce approval.
- **Chargeback that averages across teams.** "The platform spent $X" tells finance nothing. Per-team rows.
- **Pricing change applied retroactively.** A 2026-11 rate change recalculating 2026-10 chargeback produces a surprise bill. Pin pricing SHA per cost row; 2026-10 is sealed.
- **Cost recorded in two places.** The orchestrator writes a shard completion; the adapter writes a usage event; neither knows about the other. A single idempotent writer per (run, shard, backend).
- **Human-rater rejects billed at full rate.** Some vendors charge a fraction for rejected items; the pricing config must distinguish. Otherwise the estimate is 10–20% over on vendor-human runs.
- **Soft breaches silenced.** A soft breach that only writes a log entry is a soft breach that will be ignored. Page the owner; weekly digest of repeats.
- **GPU cost estimated per item, not per shard.** A cold-load overhead of 8 seconds is amortized over a shard, not every item. Estimating per item inflates the bill 20× on small datasets.
- **No reconciliation.** `SUM(cost_rows)` for the run and the `runs.dollars_spent` column drift. Pick one as the source of truth and reconcile in CI.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `GOVERN` function asks for resource allocation and accountability structures that are documented and operationalized; a per-team × per-environment × per-backend quota enforced by the submit path is the direct operationalization. `MANAGE` asks that risk prioritization be reflected in resource decisions — hard caps on the specific backends that have the worst cost-amplification risk (hosted judges, large-GPU pools) encode the organization's actual risk posture.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML04 Model Denial of Service** describes cost-amplification attacks: a prompt pattern that drives up output tokens, a runaway eval that hammers a shared judge, a stale cron that rescores the same items forever. Hard caps and pre-flight estimation are the controls. **ML06 AI Supply Chain Attacks** motivates pinning the pricing SHA and version-controlling the price table — a vendor-side price change that doubles cost is a supply-chain cost regression the platform catches at the next estimate.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0029 Denial of ML Service` is specifically the attack a cost cap defends against; the organization's own repeated, uncapped runs can be as costly as an external DoS. The combined pre-flight estimate + per-bucket hard cap is the platform's own bound on its exposure.

<!-- Local exercise context: The specific default caps ($50/$500 for dev, $1,000/$10,000 for prod), the 10% estimation safety margin, the 5% platform overhead, and the half-of-serving default for judge buckets are illustrative defaults for an internal eval platform serving a medium-sized ML org. Replace them with your organization's actual chargeback schedule, approval SLAs, and FinOps review cadence before adopting. Sibling exercises: the registry that provides pinned pricing and judge URIs is [exercise-01](../exercise-01-versioned-registry-design/SOLUTION.md); the orchestrator that consults `has_headroom` before every shard submit and whose `runs.dollars_spent` must reconcile with `cost_rows` is [exercise-02](../exercise-02-multi-runner-orchestration/SOLUTION.md); the warehouse that reads `cost_rows` as a fact table for cost analytics is [exercise-04](../exercise-04-eval-data-warehouse-and-lineage/SOLUTION.md); the CI pipeline whose per-commit eval submits must pass `check_submit` is [exercise-05](../exercise-05-eval-in-ci-with-slo/SOLUTION.md). -->
