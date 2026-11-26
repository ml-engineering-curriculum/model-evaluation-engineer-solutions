# exercise-02 — Multi-Runner Orchestration — Solution

## 1. Solution overview

An eval platform that only knows how to run on one backend is a platform that stalls every time that backend has a capacity dip, a routine upgrade, or a vendor outage. Real eval workloads are heterogeneous: a judge-driven eval wants a hosted LLM API with retries and rate-limit respect; a serving benchmark wants a dedicated GPU pool with pinned driver and tokenizer; a classical-ML eval is CPU-cheap and spot-friendly; a human-rater pipeline runs on a vendor queue and takes hours. An orchestration layer that pretends they are the same is the layer that silently drops results, double-charges the wrong budget, and reports a half-run as a pass.

The design hinges on four non-negotiables:

- **One run spec, many runner adapters.** The run spec (`RunSpec`) is the single source of truth: what to evaluate, on which dataset, with which metrics. Each runner adapter (API-LLM, GPU, CPU, vendor-human) knows how to translate that spec into its backend's units — tokens for a hosted API, batches for a GPU pool, tasks for a human queue — and how to normalize results back.
- **Shards are first-class, with idempotent retries.** A run is decomposed into shards; each shard has a stable id derived from `(run_id, item_range, runner_id)`. The runner reports per-shard status; the orchestrator retries only failed shards. Idempotency is enforced at the shard level — the same shard re-run produces the same output.
- **Backpressure and rate limits are honored, not ignored.** The orchestrator reads a backend's rate-limit response (`Retry-After`, 429, per-minute token budgets) and de-escalates fan-out; a runaway eval that hammers a hosted judge until it 429s for everyone is a platform incident, not a feature.
- **Status is a committed artifact, not an in-memory variable.** Every state transition — `queued → running → shard_failed → retrying → completed` — writes a row. A run whose status lives only in the orchestrator's process memory is a run that disappears on a deploy.

The reference answer has five deliverables:

1. A **run spec schema** (`run_spec.schema.json`) — the committed contract between callers and the orchestrator.
2. A **runner adapter interface** (`runner.py`) — `plan`, `submit`, `poll`, `fetch`, `cancel` — and three reference implementations (API-LLM, GPU-pool, vendor-human).
3. An **orchestrator** (`orchestrator.py`) that decomposes a run into shards, dispatches to the right adapter, handles retries, enforces backpressure, and writes a status log.
4. A **status model** (`status.sql`) covering `runs`, `shards`, `shard_attempts`, and `rate_limit_events`.
5. An **operational runbook** (`docs/operations.md`) covering stuck shards, saturated backends, and shard de-duplication.

This maps directly to the NIST AI RMF `MEASURE` and `MANAGE` functions: `MEASURE` asks that evaluations be "repeatable, with documented tools and assumptions"; shard-level idempotency with a committed per-shard manifest is the repeatability property. `MANAGE` asks for "documented responses to known failure modes"; the per-adapter backpressure policy and the stuck-shard runbook are the documented responses ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML04 Model Denial of Service** (an uncapped fan-out from an eval becomes a self-DoS of the shared judge backend; the rate-limit respect and per-run token budget are the control) and **ML09 Output Integrity Attacks** (a shard that silently failed and produced partial results looks the same as a shard that completed — the per-shard sha and completeness check prevent a partial run from being reported as a pass) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0029 Denial of ML Service` and `AML.T0040 ML Model Inference API Access` frame the orchestrator as a shared resource whose fan-out must be bounded by policy, not by trust ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked design and implementation

### 2.1 Run spec

```json
{
  "schema_version": 1,
  "run_id": "run-2026-11-20-abc123",
  "requested_by": "alice@team",
  "requested_at": "2026-11-20T15:00:00Z",
  "purpose": "nightly-regression",
  "dataset": "datasets/billing-chats@v4.2.1",
  "model": "models/llm-v7-candidate@sha256:...",
  "metrics": [
    "metrics/exact-match@v0.4.2",
    "metrics/semantic-f1@v0.4.2",
    "metrics/refusal-rate@v0.4.2"
  ],
  "judges": ["judges/helpfulness-v2@v1.3.0"],
  "runners": [
    {
      "name": "serving-gpu",
      "kind": "gpu-pool",
      "selectors": {"gpu_type": "H100", "pool": "eval-prod"},
      "concurrency": 64,
      "max_items": null
    },
    {
      "name": "judge-llm",
      "kind": "api-llm",
      "provider": "internal-judge",
      "concurrency": 32,
      "rate_limit_rps": 20,
      "max_items": null
    }
  ],
  "shard_strategy": {"kind": "item_range", "shard_size": 500},
  "budget": {"max_dollars": 120.0, "max_wallclock_minutes": 90},
  "retry_policy": {"max_attempts": 3, "backoff": "exp", "base_seconds": 5},
  "idempotency_key": "nightly-regression-2026-11-20"
}
```

Rules the spec enforces:

- **Every artifact is a pinned URI.** No bare names. The spec references the registry (see [exercise-01](../exercise-01-versioned-registry-design/SOLUTION.md)); a missing `@...` is rejected at the orchestrator's API.
- **Runners are named by role.** `serving-gpu` runs the candidate; `judge-llm` scores. The names appear on dashboards, in logs, and in the per-shard record; "runner 0 / runner 1" would be unreadable six months later.
- **Budget is in the spec, not an operator default.** A caller cannot submit a run that is unbounded in dollars and minutes; the orchestrator refuses.
- **`idempotency_key` is caller-scoped.** Two submits with the same key return the same run — a script that times out and retries does not spawn a parallel run.

### 2.2 Runner adapter interface

```python
"""Runner adapter: the single shape every backend implements.

The orchestrator never calls the backend directly; it calls an adapter. A
backend swap is an adapter swap, not a rewrite of the orchestrator."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal


ShardKind = Literal["item_range", "slice", "single_item"]
ShardStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


@dataclass(frozen=True)
class Shard:
    shard_id: str          # sha256 of (run_id, runner_name, item_range, model, dataset)
    run_id: str
    runner_name: str
    item_range: tuple[int, int]
    model_uri: str
    dataset_uri: str
    metrics: tuple[str, ...]
    retries_remaining: int


@dataclass
class ShardResult:
    shard_id: str
    status: ShardStatus
    predictions_uri: str | None = None
    per_item_cost: dict[str, float] = field(default_factory=dict)  # dollars / tokens / seconds
    error_kind: str | None = None                                   # rate_limit | oom | timeout | server_5xx | adapter_bug
    error_detail: str | None = None
    retry_after_seconds: int | None = None


class RunnerAdapter(ABC):
    kind: str

    @abstractmethod
    def plan(self, spec: "RunSpec", runner_cfg: dict) -> list[Shard]:
        """Decompose the run into shards for this runner. Shard ids are
        stable across replans — two plans of the same spec produce the same
        shard ids. The orchestrator calls plan() at most once per run."""

    @abstractmethod
    def submit(self, shard: Shard) -> None:
        """Enqueue the shard on the backend. MUST be idempotent on shard_id:
        a resubmit of an in-flight shard is a no-op."""

    @abstractmethod
    def poll(self, shard: Shard) -> ShardResult:
        """Return the current status. Called on a cadence; cheap."""

    @abstractmethod
    def fetch(self, shard: Shard) -> ShardResult:
        """Download the completed shard's artifacts (predictions, per-item
        cost). Called once on terminal status."""

    @abstractmethod
    def cancel(self, shard: Shard) -> None:
        """Cancel a running shard. Idempotent."""
```

Why the interface is five methods, not three:

- **`plan` is separate from `submit`.** Planning writes the shard rows before any work starts; an orchestrator crash after plan but before submit replays safely from the status table.
- **`poll` and `fetch` are separate.** Poll is high-frequency and cheap (metadata only); fetch is expensive (downloads predictions). Collapsing them makes poll a distributed-filesystem hammer.
- **`cancel` must be idempotent.** A shard already finishing when the user cancels should not error; the adapter returns silently.

### 2.3 Reference adapter — API-LLM

```python
"""API-LLM adapter: runs items through a hosted or internal LLM endpoint.

Honors three signals from the provider:
  - 429 with Retry-After → backs off that long, decrements the shared token
    budget less aggressively, raises the shard's `error_kind='rate_limit'`.
  - 5xx → exponential backoff up to retry_policy.max_attempts.
  - 4xx (non-429) → terminal failure; the shard reports `error_kind='bad_request'`
    and the orchestrator does not retry (retrying a 400 is a bug)."""

from __future__ import annotations

import time
import hashlib


class ApiLlmAdapter(RunnerAdapter):
    kind = "api-llm"

    def __init__(self, client, rate_limiter, dataset_loader) -> None:
        self._client = client
        self._rl = rate_limiter
        self._datasets = dataset_loader

    def plan(self, spec, runner_cfg):
        n = self._datasets.length(spec.dataset)
        size = spec.shard_strategy["shard_size"]
        shards = []
        for lo in range(0, n, size):
            hi = min(lo + size, n)
            sid = _shard_id(spec.run_id, runner_cfg["name"], (lo, hi), spec.model, spec.dataset)
            shards.append(Shard(
                shard_id=sid, run_id=spec.run_id, runner_name=runner_cfg["name"],
                item_range=(lo, hi), model_uri=spec.model, dataset_uri=spec.dataset,
                metrics=tuple(spec.metrics),
                retries_remaining=spec.retry_policy["max_attempts"],
            ))
        return shards

    def submit(self, shard):
        if self._status_table.is_inflight(shard.shard_id):
            return  # idempotent
        self._status_table.mark_queued(shard.shard_id)
        self._queue.enqueue(shard)

    def poll(self, shard):
        return ShardResult(
            shard_id=shard.shard_id,
            status=self._status_table.get_status(shard.shard_id),
        )

    def fetch(self, shard):
        pred_uri = self._status_table.predictions_uri(shard.shard_id)
        cost = self._status_table.cost(shard.shard_id)
        return ShardResult(
            shard_id=shard.shard_id, status="completed",
            predictions_uri=pred_uri, per_item_cost=cost,
        )

    def cancel(self, shard):
        self._status_table.mark_cancelled(shard.shard_id)


def _shard_id(run_id, runner_name, item_range, model_uri, dataset_uri) -> str:
    key = f"{run_id}|{runner_name}|{item_range[0]}-{item_range[1]}|{model_uri}|{dataset_uri}"
    return hashlib.sha256(key.encode()).hexdigest()
```

The worker that pops the queue and makes the actual API calls honors the rate limiter and writes per-item results. On a 429 it records the `Retry-After`, requeues the shard with a visible `rate_limit` event, and does not count the attempt against `retries_remaining` — rate-limit retries are not "we tried and the model failed"; they are "the shared resource asked us to slow down."

### 2.4 Reference adapter — GPU pool

```python
"""GPU-pool adapter: runs the candidate model on a dedicated inference pool.

Backpressure signal: the pool reports queue depth and reserved-GPU count.
When reserved-GPU > 0.9 * pool_size, the adapter refuses new submits and
reports `queued` status; a retry at the orchestrator's next tick picks it up."""

class GpuPoolAdapter(RunnerAdapter):
    kind = "gpu-pool"

    def __init__(self, pool_client, model_loader) -> None:
        self._pool = pool_client
        self._models = model_loader

    def plan(self, spec, runner_cfg):
        # same item_range decomposition as API-LLM; see above
        ...

    def submit(self, shard):
        depth, size = self._pool.queue_depth(), self._pool.size()
        if depth > 0.9 * size:
            self._status_table.record_backpressure(shard.shard_id, depth=depth, size=size)
            return  # not an error; orchestrator will retry submit
        self._pool.enqueue({
            "shard_id": shard.shard_id,
            "model_uri": shard.model_uri,
            "dataset_uri": shard.dataset_uri,
            "item_range": shard.item_range,
            "selectors": {"gpu_type": "H100", "pool": "eval-prod"},
        })
        self._status_table.mark_queued(shard.shard_id)

    # poll, fetch, cancel: analogous to api-llm adapter.
```

Rules the adapter enforces:

- **Backpressure is a first-class return, not an exception.** A shard that could not be submitted because the pool is full is still `queued` from the orchestrator's perspective; the next tick retries. A 429-like exception would double-count attempts.
- **GPU type is a selector, not a runner kind.** `H100` vs. `A100` is a selector against the pool; one adapter serves many pools. A new GPU type is a selector entry, not a new adapter.
- **Model download is adapter-local.** The adapter pins the model weights into its own cache and reports a `model_resolved_sha` on the first submit; subsequent shards in the run reuse the cached weights. A model re-download per shard is a cost bug.

### 2.5 Reference adapter — vendor-human

```python
"""Vendor-human adapter: submits items to a human-rating vendor queue.

The surface is different: shards are tasks, status transitions are slow
(hours), and completion is a vendor webhook. The adapter normalizes the
external surface to the same five-method shape so the orchestrator does
not special-case it."""

class VendorHumanAdapter(RunnerAdapter):
    kind = "vendor-human"

    def plan(self, spec, runner_cfg):
        # shards are per-item or per-small-batch (e.g., 20 items per shard)
        ...

    def submit(self, shard):
        self._vendor.create_task(
            task_id=shard.shard_id,
            instruction=self._load_instruction(shard),
            items=self._load_items(shard),
            qualifications={"language": shard.metrics}, # ...
        )
        self._status_table.mark_queued(shard.shard_id)

    # poll reads vendor status; fetch downloads the labels. A webhook also
    # writes directly to `shards.status` when the vendor reports completion,
    # so the orchestrator observes the terminal state on either path.
```

### 2.6 Orchestrator

```python
"""Orchestrator: fans out a RunSpec across adapters, collects results, enforces
budget and retry policy, writes the status trail.

Design:
  - One tick loop per run. Each tick: resubmit backpressure-deferred shards,
    poll in-flight shards, fetch completed, retry failed per policy, update
    the run's aggregate status.
  - No in-memory state. The orchestrator process can die between any two
    ticks and resume from the status table.
  - Budget guard: before every submit, the orchestrator asks the cost
    controller (see mod-111 exercise-03) whether the run has headroom; if
    not, pending shards go to `held_budget` and the run reports `paused`."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RunState:
    run_id: str
    status: str                       # queued|running|paused|completed|failed|cancelled
    shards_total: int
    shards_completed: int
    shards_failed: int
    dollars_spent: float
    wallclock_started: str


class Orchestrator:
    def __init__(self, adapters, cost_controller, status) -> None:
        self._adapters = adapters       # kind -> RunnerAdapter
        self._cost = cost_controller
        self._status = status

    def submit_run(self, spec) -> str:
        if self._status.exists_by_idempotency(spec.idempotency_key):
            return self._status.run_id_by_idempotency(spec.idempotency_key)
        self._status.write_run(spec)
        for runner_cfg in spec.runners:
            adapter = self._adapters[runner_cfg["kind"]]
            shards = adapter.plan(spec, runner_cfg)
            self._status.write_shards(spec.run_id, shards)
        return spec.run_id

    def tick(self, run_id) -> RunState:
        spec = self._status.load_spec(run_id)
        state = self._status.load_state(run_id)
        if state.status in ("completed", "failed", "cancelled"):
            return state

        if not self._cost.has_headroom(run_id, spec.budget):
            self._status.mark_paused(run_id, reason="budget_exceeded")
            return self._status.load_state(run_id)

        for shard in self._status.pending_shards(run_id):
            adapter = self._adapters[self._status.runner_kind(shard)]
            adapter.submit(shard)

        for shard in self._status.inflight_shards(run_id):
            adapter = self._adapters[self._status.runner_kind(shard)]
            result = adapter.poll(shard)
            if result.status == "completed":
                self._status.record_completion(shard, adapter.fetch(shard))
            elif result.status == "failed":
                self._handle_failure(shard, result)

        return self._status.recompute_state(run_id)

    def _handle_failure(self, shard, result):
        if result.error_kind == "rate_limit":
            # not a retry attempt; just defer
            self._status.defer(shard, after_seconds=result.retry_after_seconds or 30)
            return
        if result.error_kind == "bad_request":
            # 4xx is terminal; do not retry a broken input
            self._status.mark_terminal_failure(shard, result)
            return
        remaining = self._status.decrement_retries(shard)
        if remaining <= 0:
            self._status.mark_terminal_failure(shard, result)
            return
        self._status.requeue(shard, backoff_seconds=_backoff(shard))
```

Rules the orchestrator enforces:

- **Idempotency key on `submit_run`.** A caller that retries a submit that already succeeded gets the same `run_id`, not a parallel run.
- **The `tick` loop is the only state-advancing path.** No direct updates from webhooks or callbacks; webhooks write intermediate rows, `tick` observes them. Debugging a race condition in one method is tractable; debugging a race across four is not.
- **Rate-limit backoffs do not consume retry attempts.** A run that gets rate-limited 20 times in a row should not exhaust its retries and fail.
- **Budget exceedance pauses; it does not cancel.** The on-call engineer may raise the budget or let the run die; the orchestrator does not make that decision.

### 2.7 Status model

```sql
CREATE TABLE runs (
    run_id              TEXT PRIMARY KEY,
    idempotency_key     TEXT UNIQUE,
    spec_sha256         TEXT NOT NULL,
    status              TEXT NOT NULL,         -- queued|running|paused|completed|failed|cancelled
    requested_by        TEXT NOT NULL,
    requested_at        TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    dollars_budget      NUMERIC NOT NULL,
    dollars_spent       NUMERIC NOT NULL DEFAULT 0,
    wallclock_budget_s  INTEGER NOT NULL
);

CREATE TABLE shards (
    shard_id            TEXT PRIMARY KEY,      -- sha256(run_id, runner_name, item_range, model, dataset)
    run_id              TEXT NOT NULL REFERENCES runs(run_id),
    runner_name         TEXT NOT NULL,
    runner_kind         TEXT NOT NULL,
    item_range_lo       INTEGER NOT NULL,
    item_range_hi       INTEGER NOT NULL,
    model_uri           TEXT NOT NULL,
    dataset_uri         TEXT NOT NULL,
    status              TEXT NOT NULL,         -- queued|running|completed|failed|cancelled|deferred
    retries_remaining   INTEGER NOT NULL,
    predictions_uri     TEXT,
    cost_dollars        NUMERIC,
    completed_at        TIMESTAMPTZ
);

CREATE TABLE shard_attempts (
    attempt_id          BIGSERIAL PRIMARY KEY,
    shard_id            TEXT NOT NULL REFERENCES shards(shard_id),
    attempt_number      INTEGER NOT NULL,
    started_at          TIMESTAMPTZ NOT NULL,
    ended_at            TIMESTAMPTZ,
    status              TEXT NOT NULL,         -- running|completed|failed|cancelled|rate_limited
    error_kind          TEXT,
    error_detail        TEXT,
    cost_dollars        NUMERIC
);

CREATE TABLE rate_limit_events (
    id                  BIGSERIAL PRIMARY KEY,
    run_id              TEXT NOT NULL,
    runner_name         TEXT NOT NULL,
    occurred_at         TIMESTAMPTZ NOT NULL,
    retry_after_s       INTEGER,
    provider_response   TEXT
);
```

Rules the schema enforces:

- **`shards.shard_id` is the content-hash of its definition.** Two independent orchestrators planning the same run compute the same ids; a resubmitted shard is a no-op.
- **`shard_attempts` is append-only.** Every attempt is a row. The number of attempts never decreases; the `status` is the terminal label.
- **`rate_limit_events` is separate from `shard_attempts`.** A rate-limit does not fail a shard; it defers. Mixing them conflates "the model was unreachable" with "we asked too fast."

### 2.8 Operational runbook

```markdown
# docs/operations.md (excerpt)

## Stuck shard (status=running, no update > 2× expected duration)
1. Grafana panel "Longest running shards" surfaces `shard_id`, `runner_name`, `started_at`.
2. Call `poll` on the adapter directly; if the backend confirms completion, the webhook was lost — reconcile with `fetch`.
3. If the backend reports in-flight, raise the shard's timeout once; a second stall is a cancel and manual replan.

## Saturated backend (pool queue_depth > 0.95 for > 10 min)
1. The orchestrator will self-throttle (adapter refuses submit); no action needed short-term.
2. Check whether one run is dominating: `SELECT run_id, count(*) FROM shards WHERE status='queued' GROUP BY run_id ORDER BY 2 DESC`.
3. If one run is > 70% of queued shards, pause it (operator action) and let the pool drain.

## Duplicate run submission
1. A caller that re-submits with the same `idempotency_key` gets the same `run_id`; no action.
2. A caller that re-submits with a different key but identical spec SHA gets a new run; this is by design — two intentional runs are allowed. Dashboards highlight when spec SHAs match within a short window.

## Rate-limit storm
1. `rate_limit_events` spikes trigger the "Judge backend throttled" alert.
2. First-touch action: throttle `concurrency` on the judge adapter by 50% at the platform level (a run-time knob, not a run-spec edit).
3. Escalation: pause runs with the largest judge-shard counts first.
```

## 3. Validation steps

1. **Shard id stability.** Two independent `plan()` calls for the same spec produce the same shard ids; a test pins the expected hex digest for a fixed input.
2. **Idempotent `submit_run`.** Two submits with the same idempotency key return the same `run_id`; the status table has exactly one `runs` row.
3. **Idempotent `submit(shard)`.** Two calls on the same shard result in one queue entry; a test observes `queue.enqueue` is called exactly once.
4. **Rate-limit retries do not consume attempts.** A synthetic adapter that returns 429 five times then succeeds completes with `retries_remaining` unchanged and the `rate_limit_events` table populated five times.
5. **4xx is terminal.** A synthetic adapter that returns a 400 fails the shard immediately; the orchestrator does not retry; the `attempt_number` is 1.
6. **Backpressure does not count as a failure.** A GPU adapter returning "pool full" causes the shard to remain `queued`; no `shard_attempts` row is written; the next tick retries.
7. **Budget pause.** A run whose `dollars_spent + projected > dollars_budget` transitions to `paused` with `reason='budget_exceeded'`; no further submits occur until the budget is raised or the run is cancelled.
8. **Completeness check.** A run's `completed` state requires `shards_completed == shards_total`; a run with partial completion cannot be reported as "ship" by downstream gates. The predictions blob SHA is verified against the manifest.
9. **Crash resume.** Kill the orchestrator between `plan` and `submit`; restart; the run resumes without duplicating shards or losing any. Test harness kills at every interior state transition and asserts eventual consistency.
10. **Cancel is idempotent.** Two `cancel` calls on a running shard result in one `cancelled` row and one adapter-level cancellation; a cancel on a terminal shard is a no-op.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the orchestrator being **a resumable control loop with a per-shard ledger**, not a workflow DSL.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | RunSpec pins every artifact URI and every budget | 1 | Spec rejects bare names; no spec has an unbounded dollar or wallclock budget. |
| R2 | Adapter interface is five methods and every adapter implements them | 1 | `plan/submit/poll/fetch/cancel` present; conformance test runs against each. |
| R3 | Shard ids are content-addressed and stable across replans | 1 | Sha of `(run_id, runner_name, item_range, model, dataset)`; test pins the hex. |
| R4 | Status transitions write rows; no in-memory-only state | 2 | `runs`, `shards`, `shard_attempts` tables; crash-resume test passes. |
| R5 | Rate-limit backoff does not consume retry attempts | 1 | Synthetic 429-storm test; `rate_limit_events` populated; `retries_remaining` unchanged. |
| R6 | Backpressure is a first-class return from `submit`, not an exception | 1 | GPU adapter reports backpressure; orchestrator reruns on next tick. |
| R7 | Budget exceedance pauses; operator decides to resume or cancel | 1 | Pause test; no further submits; status `paused` with reason. |
| R8 | Completeness check before "completed"; predictions SHA verified | 1 | A run with any shard not `completed` cannot be `completed`; downstream gate reads only verified blobs. |
| R9 | Operational runbook names stuck-shard, saturated-backend, duplicate-submission, rate-limit-storm | 1 | `docs/operations.md` has one section per failure mode with a first-touch and escalation. |

**Passing bar:** 7 / 10. R4 is non-negotiable — an orchestrator whose state is a process variable has lost results every time it was deployed. R8 is the second non-negotiable: a half-complete run reported as `ship` is the worst-case outcome.

Reviewer checklist:

- [ ] Every run references pinned URIs (datasets, metrics, judges, model).
- [ ] Shard ids match the content-hash formula; replan is a no-op.
- [ ] A test that kills the orchestrator mid-run resumes without duplicated or lost shards.
- [ ] A 429 storm does not fail the run; `rate_limit_events` has rows.
- [ ] GPU-pool backpressure defers submissions without counting attempts.
- [ ] Budget exceedance pauses the run; the operator can resume or cancel.
- [ ] A run's `completed` status is gated on all shards complete and all predictions SHAs verified.
- [ ] `docs/operations.md` covers the four named failure modes with first-touch and escalation.

## 5. Common mistakes

- **One runner kind, many special cases.** An "API-LLM" adapter that also handles GPU pools via flags is a four-year maintenance liability. Five methods, one kind each.
- **Shard id is a UUID generated at submit.** Now `plan` is not idempotent — a replan after a crash produces different ids and the orchestrator loses the ability to deduplicate. Content-address the id.
- **Status kept in the orchestrator process memory.** A deploy loses the run. Every transition is a row.
- **Retrying a 429 as a failure.** A rate-limited shard that burns three retries counts as a run-level failure; the next nightly fails on the same backend. Separate `rate_limit` from `error`.
- **Retrying a 400.** A bad-request response (malformed item, unsupported language) will keep being a bad request. Terminal.
- **Backpressure thrown as an exception.** The queue depth check in a `submit` that raises is indistinguishable from a backend crash in the status table. Return a sentinel; the orchestrator does not mark an attempt.
- **Webhooks write terminal state directly.** The webhook and the `tick` loop both write to the same row; a race results in lost updates. Webhooks write intermediate rows; `tick` promotes.
- **Model re-download per shard.** Shards 1..N each fetch the model weights. The first shard should download and pin; later shards hit the cache.
- **Idempotency key not scoped to caller.** Two independent callers with the same key (`nightly`) collide. Namespace the key per caller or make it a per-caller table.
- **Budget check at the end of the run.** "We spent $800 on a $120 budget" is a post-mortem, not a control. Check before every submit.
- **No shard-level predictions SHA.** The downstream gate reads a blob that was partially written during a shard failure and scores it as a shipping candidate. Verify SHA on fetch; refuse to score a shard whose blob does not match its manifest.
- **"Completed" when `shards_failed > 0`.** A run with 998 of 1000 shards complete is not complete. Completeness check or the gate is scoring on 99.8% of the eval set and calling it a pass.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function asks for repeatable evaluations with documented tools; shard-level idempotency plus the content-addressed shard id plus the committed adapter interface is the repeatability property. The `MANAGE` function asks for documented responses to failure modes; the operational runbook's named failure modes (stuck shard, saturated backend, rate-limit storm, duplicate submit) are the documented responses.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML04 Model Denial of Service** is the primary threat: an uncapped eval fan-out onto a shared judge backend is a self-DoS; adapter-level rate-limit respect and per-run concurrency caps are the control. **ML09 Output Integrity Attacks** motivates the shard completeness check and predictions-SHA verification — a partially-completed shard looks the same as a completed one from the aggregate.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0029 Denial of ML Service` and `AML.T0040 ML Model Inference API Access` describe shared inference resources as a defended asset; bounded fan-out, honored rate limits, and committed per-run budgets are the controls that prevent an eval platform from becoming a DoS vector against the production serving plane.

<!-- Local exercise context: The specific shard size (500 items), the 0.9 pool-utilization backpressure threshold, the 30-second rate-limit defer default, and the three-attempt retry policy are illustrative defaults for a nightly LLM regression eval. Replace them with your platform's shard-size sweet spot (measured by p99 completion time per shard), your pool's healthy-utilization target, and your providers' documented retry semantics before adopting. Sibling exercises: the registry whose URIs every run spec resolves against is [exercise-01](../exercise-01-versioned-registry-design/SOLUTION.md); the cost controller the orchestrator consults for `has_headroom` is [exercise-03](../exercise-03-platform-cost-controls/SOLUTION.md); the warehouse that reads the completed shard rows as a fact table is [exercise-04](../exercise-04-eval-data-warehouse-and-lineage/SOLUTION.md); the CI pipeline that submits a RunSpec per commit is [exercise-05](../exercise-05-eval-in-ci-with-slo/SOLUTION.md). -->
