# exercise-06 — MLPerf-Style Serving Benchmark — Solution

## 1. Solution overview

A serving benchmark is the artifact that turns "this model is fast" from a feeling into a replayable number. The standard every production team benchmarks against is **MLPerf Inference**, maintained by MLCommons. MLPerf Inference exists because the "what is the latency?" question fragments the moment you ask it: latency *at what batch size, what shape mix, what concurrency, what wait-for-arrival policy, what SLO ceiling?* MLPerf fixes the experimental protocol so numbers from different runs mean the same thing. The committed benchmark **declares**:

- the **scenario** (SingleStream, MultiStream, Server, or Offline) — each models a different real-world use pattern,
- the **loadgen** behavior that issues queries — arrival distribution, warm-up, run duration,
- the **accuracy check** — a required quality threshold the system must meet during the performance run,
- the **result metric** — the specific latency or throughput number the scenario reports, measured under the loadgen's distribution,
- the **compliance fences** — the pinned version of the harness, dataset, and runner, so a reported number is reproducible.

An "MLPerf-style" benchmark is a benchmark that adopts these conventions for a non-closed-division model. The deliverable is not a competitive submission; it is a committed harness, a committed dataset slice, and a committed report that a reviewer can rerun.

The reference answer has five deliverables:

1. A **scenario declaration** — which MLPerf-style scenarios the benchmark runs (Server + Offline is the normal pair for LLM serving), with the SLO for Server.
2. A **load generator** — a traffic generator that models the declared arrival process (Poisson for Server, flood for Offline), issues queries at a target QPS, and records per-query timestamps.
3. An **accuracy validator** — a scoring pass that proves the system under test met the quality threshold during (or alongside) the performance run.
4. A **result report** — the metrics the scenario defines (Server: p99 latency at target QPS; Offline: samples-per-second throughput), with CI, and a compliance section naming every pinned artifact.
5. A **manifest** — the row another engineer uses to rerun: model id, serving config, scenarios, QPS schedule, SLOs, dataset SHA, warm-up and run durations.

This maps to the NIST AI RMF `MEASURE` function, which asks for metrics that are "tested, documented, and tied to an identified operational context" and evaluations that are "repeatable, with documented tools and assumptions" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML09 Output Integrity Attacks** — a benchmark that trades accuracy for throughput (e.g., by truncating outputs under load) is attacking the eval, which is why MLPerf requires an accuracy pass to validate a performance run ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0043 Craft Adversarial Data` motivates the benchmark's dataset pinning — a slice chosen at run time can under-represent the shapes that produce the tail ([MITRE ATLAS](https://atlas.mitre.org/)). The scenario definitions and compliance conventions below follow the MLPerf Inference project's published rules; see the reference in §6.

The reference solution is **not** an MLPerf submission. The deliverable is a benchmark inside a product team's repository that borrows MLPerf's structure — scenario, loadgen, accuracy-gated performance run, pinned harness.

## 2. Worked implementation

### 2.1 Scenarios

Pin which scenarios the benchmark runs. For a chat / completion LLM, the typical pair is:

- **Server** — queries arrive on a Poisson process at a target QPS; the metric is **p99 (or committed percentile) end-to-end latency** at the target. The scenario passes if p99 ≤ SLO at the target QPS; the engineering question is "what is the max QPS the system can sustain within SLO?"
- **Offline** — all queries are available at the start of the run; the metric is **samples per second throughput** over the full run. No per-query latency ceiling. Models batch-inference workloads.

Sibling MLPerf scenarios exist (SingleStream is latency-of-one-query; MultiStream is latency-of-a-fixed-concurrent-batch) and are appropriate for mobile / edge; they are out of scope for a serving benchmark unless the product is a one-query-at-a-time path.

Rules:

- **The scenario is committed.** A benchmark that is "Server for p99 if it looks good, Offline throughput if p99 is bad" is a vibe. Pin.
- **The target QPS is committed per scenario.** Server at 10 QPS and Server at 100 QPS are two benchmarks with different numbers; the manifest pins which.
- **The SLO is committed.** Server's pass/fail requires an SLO number ("p99 ≤ 500 ms"). An unspecified SLO makes the result unreadable.

### 2.2 Load generator (`loadgen.py`)

The loadgen is the single source of truth for the arrival process. It owns every per-query timestamp.

```python
"""MLPerf-style load generator (simplified).

Server scenario: Poisson arrivals at target_qps. Queries are issued
asynchronously; per-query end-to-end latency is measured as
(response_received - query_scheduled_time), including queue wait.

Offline scenario: all queries are available at t=0; the generator submits
them as fast as the system under test accepts; throughput is
(samples_completed / total_wall_clock).

Loadgen records:
- scheduled_ts, sent_ts, received_ts per query
- per-query response payload hash + token counts
A later accuracy pass rereads scheduled_ts only; it does not re-issue."""

from __future__ import annotations
import asyncio
import math
import random
import time
from dataclasses import dataclass, field


@dataclass
class QueryRecord:
    query_id: str
    scheduled_ts: float
    sent_ts: float
    received_ts: float
    status: str
    response_sha256: str | None
    tokens_out: int
    error: str | None = None


@dataclass
class LoadgenConfig:
    scenario: str                  # "server" | "offline"
    target_qps: float
    duration_s: float
    warmup_s: float
    seed: int
    max_in_flight: int


def _poisson_interarrivals(rate: float, duration: float, seed: int):
    rng = random.Random(seed)
    t = 0.0
    while t < duration:
        t += rng.expovariate(rate)
        yield t


async def run_server(client, queries, cfg: LoadgenConfig) -> list[QueryRecord]:
    """Server scenario: Poisson arrivals, async dispatch, capped in-flight.

    `client.send(query)` must return an awaitable that resolves with the
    response payload. The loadgen owns timestamps; the client does not."""
    records: list[QueryRecord] = []
    semaphore = asyncio.Semaphore(cfg.max_in_flight)
    start_wall = time.monotonic()
    tasks = []

    async def _one(q, sched_t):
        # Wait until the scheduled time (Poisson-chosen); then dispatch.
        sleep_for = sched_t - (time.monotonic() - start_wall)
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)
        async with semaphore:
            sent_ts = time.monotonic()
            try:
                resp = await client.send(q)
                recv_ts = time.monotonic()
                records.append(QueryRecord(
                    query_id=q["query_id"],
                    scheduled_ts=sched_t,
                    sent_ts=sent_ts - start_wall,
                    received_ts=recv_ts - start_wall,
                    status="ok",
                    response_sha256=resp["sha256"],
                    tokens_out=resp["tokens_out"],
                ))
            except Exception as e:
                recv_ts = time.monotonic()
                records.append(QueryRecord(
                    query_id=q["query_id"],
                    scheduled_ts=sched_t,
                    sent_ts=sent_ts - start_wall,
                    received_ts=recv_ts - start_wall,
                    status="error",
                    response_sha256=None,
                    tokens_out=0,
                    error=str(e),
                ))

    arrivals = _poisson_interarrivals(cfg.target_qps, cfg.duration_s, cfg.seed)
    for q, sched_t in zip(queries, arrivals):
        tasks.append(asyncio.create_task(_one(q, sched_t)))
    await asyncio.gather(*tasks)
    return records


async def run_offline(client, queries, cfg: LoadgenConfig) -> list[QueryRecord]:
    """Offline scenario: fire as fast as the client accepts, up to
    max_in_flight. End of run = when all queries have returned."""
    records: list[QueryRecord] = []
    semaphore = asyncio.Semaphore(cfg.max_in_flight)
    start_wall = time.monotonic()

    async def _one(q):
        async with semaphore:
            sched = time.monotonic() - start_wall
            sent = sched  # offline has no scheduled wait
            resp = await client.send(q)
            recv = time.monotonic() - start_wall
            records.append(QueryRecord(
                query_id=q["query_id"], scheduled_ts=sched, sent_ts=sent,
                received_ts=recv, status="ok",
                response_sha256=resp["sha256"], tokens_out=resp["tokens_out"],
            ))

    await asyncio.gather(*[_one(q) for q in queries])
    return records
```

Design rules worth calling out:

- **Arrival process is Poisson in Server, not uniform.** Uniform arrivals understate tail latency because they never produce a burst. Poisson matches the arrival shape of a real request stream well enough to surface the tail.
- **Loadgen owns the clock.** The system-under-test must not supply timestamps; a benchmark that reads `received_ts` from the server's response is subject to clock skew and server-side rewrites.
- **Monotonic clock.** `time.monotonic()` — an NTP step mid-benchmark would re-attribute latencies retroactively.
- **Warm-up excluded from metrics.** The first `warmup_s` seconds are run but not scored (JIT, autoscale, cache priming). The manifest commits the warm-up duration.
- **Scheduled / sent / received timestamps all recorded.** `received - scheduled` is end-to-end latency; `received - sent` is per-request service time; the difference is queue wait. Reporting one and losing the others is throwing away diagnostic power.
- **Max in-flight is a committed cap.** Server scenario queues above the cap are either dropped (reported as errors) or run on; a missing cap turns tail latency into "whatever the OS kernel decided."

### 2.3 Accuracy validator (`accuracy.py`)

MLPerf's rule: a performance run is invalid if the system under test does not pass an accuracy threshold on the same dataset. The validator re-scores the responses and compares to the committed quality threshold.

```python
"""Accuracy validator for the performance run.

The validator reads loadgen.jsonl and the committed ground_truth.jsonl and
emits an accuracy.json. The performance metric reported in the main report
is invalid if accuracy < committed_threshold."""

from __future__ import annotations
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class AccuracyResult:
    n: int
    score: float
    threshold: float
    passed: bool


def validate(loadgen_records, ground_truth, scorer, threshold: float) -> AccuracyResult:
    y = []
    for r in loadgen_records:
        if r.status != "ok":
            y.append(0.0)
            continue
        truth = ground_truth[r.query_id]
        y.append(float(scorer(r.response_sha256, truth)))
    mean = sum(y) / max(len(y), 1)
    return AccuracyResult(
        n=len(y), score=mean, threshold=threshold, passed=mean >= threshold,
    )
```

Rules:

- **Errors count as 0, not as missing.** A system that drops queries under load is a system that is fast only by cheating; counting drops as 0 preserves the correct accuracy denominator.
- **The scorer is the committed scorer from the regression suite** (see [exercise-01](../exercise-01-offline-regression-suite-with-gates/SOLUTION.md)); the benchmark does not invent an easier scorer.
- **Threshold is committed in the manifest** and cannot be loosened to rescue a failing run.
- **Accuracy and performance can be two runs** if the accuracy scorer is expensive (slow judge). The manifest pins both run ids and declares the pairing.

### 2.4 Report and manifest

`report_<run_id>.md` opens with the pass/fail and the headline metric:

```markdown
# Benchmark run bench_llm_v7_2026-11-20 (Server, 20 QPS)

**Result:** pass  (p99 e2e = 412 ms ≤ SLO 500 ms; accuracy 0.78 ≥ threshold 0.75)

## Latency (Server scenario, 20 QPS, 20-min run excl. 2-min warmup)
| | p50 | p90 | p99 | p99.9 | max |
|---|---|---|---|---|---|
| e2e_ms (scheduled→received) | 184 | 290 | 412 | 612 | 1104 |
| service_ms (sent→received)  | 180 | 285 | 395 | 582 | 981  |
| queue_ms (scheduled→sent)   |   2 |   8 |  24 |   58 |  110 |

CI from 1000-iter bootstrap on per-query latencies (seed=20261120):
p99 e2e [401, 423] ms

## Throughput (Offline scenario, 2048 queries)
| | value |
|---|---|
| samples/s | 44.2 |
| CI | [43.8, 44.6] |

## Accuracy (same dataset slice, judge=pairwise-v2)
| | value |
|---|---|
| n | 2048 |
| score | 0.78 |
| threshold | 0.75 |
| passed | yes |

## Error accounting
| | count | fraction |
|---|---|---|
| ok | 2042 | 0.997 |
| error:timeout | 4 | 0.002 |
| error:5xx | 2 | 0.001 |
```

Manifest `bench_run.yaml`:

```yaml
run_id: bench_llm_v7_2026-11-20
scenarios:
  - name: server
    target_qps: 20
    percentile: 99
    slo_ms: 500
    duration_s: 1200
    warmup_s: 120
    max_in_flight: 256
    seed: 20261120
  - name: offline
    sample_count: 2048
    max_in_flight: 256
    seed: 20261120
system_under_test:
  model_id: llm-v7
  model_build_sha: <git sha>
  serving_image: ghcr.io/org/serving@sha256:<digest>
  gpu: 1x H100 (SXM) 80GB
  tp: 1
  pp: 1
  max_batch_tokens: 4096
  kv_cache: enabled
dataset:
  name: bench_shapes_v2
  slice_sha256: <sha256>
  shape_mix_rationale: "p50/p95 prompt tokens ~800/3200 from 28d serving"
accuracy:
  judge: pairwise-v2
  threshold: 0.75
compliance:
  harness_commit: <git sha>
  loadgen_version: v1.3 (project-local)
  prometheus_rules_commit: <sha of rules/eval.yml>
```

### 2.5 Shape mix

The dataset is not a random sample; it is a committed **shape mix** that matches the production distribution of prompt lengths and output lengths. A benchmark on a dataset whose prompts are uniformly 100 tokens misses the long-prompt tail that dominates p99 on the real workload.

Rules:

- **Prompt-length distribution of the benchmark slice matches a committed production target** (p50 / p95 / p99). The target is derived from a snapshot of serving logs with its own SHA and date.
- **Output-length distribution likewise.** A generation benchmark that caps outputs at 128 tokens has no information about the 2k-token completion tail.
- **The slice is committed.** Random re-sampling at run time breaks reproducibility; a committed slice with a SHA does not.
- **The scorer tolerates the shape mix.** A judge that fails on 3 k-token inputs cannot be used to validate accuracy on a 3 k-token benchmark; pin the judge version and known-supported input ranges.

### 2.6 Compliance fences

The compliance block is the row that determines whether a number can be compared to a prior run.

- **Harness commit.** The code that produced the number is at a committed git sha. A patched harness is a new benchmark.
- **Serving image digest.** `image@sha256:<digest>` — not a tag. Tags move; digests don't.
- **GPU model and count.** `1x H100 80GB SXM` is a different benchmark from `1x H100 80GB PCIe`.
- **Parallelism and batching.** `tp`, `pp`, `max_batch_tokens`, and KV-cache enablement are first-class fields; a tp=2 run is not directly comparable to tp=1.
- **Dataset SHA.** The slice is pinned.
- **Loadgen version.** A loadgen change is a new benchmark.

A run that is missing any of the above in its manifest is recorded as `compliance=partial` in the index and cannot be used as a baseline for a future comparison.

## 3. Validation steps

1. **Loadgen determinism.** Rerun with the same seed, duration, and max-in-flight; the sequence of `scheduled_ts` is byte-identical (the Poisson generator is seeded).
2. **Clock discipline.** All timestamps are `time.monotonic()`-based and strictly non-decreasing within a single `QueryRecord`; `scheduled_ts <= sent_ts <= received_ts`.
3. **Warm-up excluded from reporting.** Scoring the first `warmup_s` seconds separately produces a distinct `warmup_p99` field; the headline p99 excludes warm-up records.
4. **Accuracy gate works.** A synthetic run whose responses deliberately miss ground truth produces `passed=False` and the headline performance metric is tagged `invalid=accuracy_failed`.
5. **Error-counted-as-0.** A synthetic run with 30% timeouts has accuracy ≈ 0.7× the all-ok rate; the accuracy validator's n matches the loadgen's scheduled count.
6. **Latency decomposition reconciles.** For every query, `received_ts - scheduled_ts == (received_ts - sent_ts) + (sent_ts - scheduled_ts)` to within the clock resolution.
7. **Bootstrap CI reproducible.** The CI on p99 is reproduced byte-identical with the committed seed; two reruns produce the same `[lo, hi]`.
8. **Server respects target QPS.** Over the duration, `(count / duration)` matches the target QPS within a small multiplicative margin; a run that under-paces (because the system blocks) is flagged `pacing_broken` rather than silently reporting an easier latency.
9. **Max-in-flight enforced.** A chaos test sets `max_in_flight=16` and a client that artificially slows: concurrent in-flight never exceeds 16 and queued queries go to error with an explicit reason.
10. **Shape-mix validation.** The benchmark dataset's prompt-length quantiles match the committed target quantiles within a committed tolerance; otherwise the benchmark refuses to run.
11. **Compliance fence completeness.** A manifest with any missing compliance field produces `compliance=partial` and the index links do not include it as a baseline candidate.

## 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Scenarios are declared (at least Server + Offline) with target and SLO | 2 | Manifest `scenarios:`; Server has `target_qps`, `percentile`, `slo_ms`. |
| R2 | Loadgen issues on a committed arrival process (Poisson for Server) and owns timestamps | 2 | `loadgen.py`; determinism test with seeded Poisson. |
| R3 | Latency decomposed into queue + service + end-to-end | 1 | Per-query record carries all three timestamps; report table shows the decomposition. |
| R4 | Accuracy validator gates the performance result | 2 | A failing accuracy run invalidates the perf report. |
| R5 | Warm-up is committed and excluded | 1 | Manifest `warmup_s`; separate `warmup_p99` reported. |
| R6 | Compliance fences pinned: harness commit, image digest, GPU, tp/pp, dataset SHA | 1 | Manifest `compliance:` has every field; partial manifests flagged. |
| R7 | Shape-mix matches a committed production target | 1 | Dataset's length quantiles match target within tolerance; check runs pre-benchmark. |

**Passing bar:** 7 / 10. R2 and R4 are non-negotiable — a loadgen that reports server-side timestamps is measuring the server's narrative, not the user's experience; a perf result without an accuracy gate ships a fast-but-wrong model.

Reviewer checklist:

- [ ] Scenarios declared with QPS, percentile, SLO; warm-up excluded.
- [ ] Loadgen uses Poisson arrivals for Server; monotonic clock; owns all three timestamps.
- [ ] Latency decomposition (queue / service / end-to-end) is in the report.
- [ ] Accuracy validator passes before the performance metric is accepted.
- [ ] Compliance manifest has harness commit, image digest, GPU, tp/pp, dataset SHA, loadgen version.
- [ ] Reruns with the same seed produce byte-identical arrival sequence and per-query timestamps (within clock resolution).
- [ ] Shape-mix quantiles match the committed production target.
- [ ] Errors count as 0 for accuracy; error-rate reported separately.

## 5. Common mistakes

- **Uniform arrivals.** Uniform QPS misses bursts; the p99 is a flattered number. Poisson.
- **Server-side timestamps.** The server reports `elapsed_ms` and you believe it. Clock skew, CPU-stall rewrites, and queue-manipulation bugs are invisible. Loadgen owns the clock.
- **No warm-up.** The first minute includes JIT, cache priming, and autoscale. A p99 computed over warm-up is a different number from one over steady state.
- **One scenario only.** Server without Offline leaves the question "could this model serve a 2048-query batch in a reasonable time?" unanswered. Reporting both is cheap.
- **Report p99 without a CI.** p99 on 10k samples has a non-trivial CI; a point estimate implies a precision that isn't there. Bootstrap.
- **Accuracy pass skipped.** The team reports a beautiful p99 on a model that silently truncates to 32 tokens. MLPerf does not accept a perf run without an accuracy run, and neither should this benchmark.
- **Shape mix not matched to production.** A benchmark whose prompts are all 128 tokens finds no tail; production tail lives at 4k-prompt, 2k-output requests.
- **Dataset not pinned.** Re-sampling at run time means no two runs can be compared. Pin the slice SHA.
- **Serving image by tag, not digest.** Tags move. `@sha256:<digest>` does not.
- **Max-in-flight unset.** The OS decides the concurrency. Two runs on two kernels disagree about what the tail is; no one can reproduce.
- **Dropped queries counted as success.** The system's "fast" number is "fast on the queries that didn't drop." Dropped queries count against accuracy (as 0) and are reported separately as error rate.
- **Averaging latency.** The mean is dominated by nothing interesting; the p99 is the production-relevant number. Always report tail percentiles.
- **Loadgen pacing broken.** Under heavy load the loadgen is slow to schedule; the "target QPS" number is a lie. Flag `pacing_broken` when observed QPS diverges materially from target; do not silently report a tighter p99.
- **Comparing runs across GPU types.** `H100 PCIe` is not `H100 SXM`. Compliance fence guards against misuses.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. `MEASURE` asks for metrics that are "tested, documented, and tied to an identified operational context" — a committed scenario, SLO, shape mix, and compliance manifest are the direct operationalization for a serving benchmark.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** motivates the accuracy-gated performance rule — a system that trades accuracy for throughput is attacking the benchmark, not winning it.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0043 Craft Adversarial Data` motivates dataset pinning and shape-mix validation — a slice chosen at run time can suppress exactly the shapes that break the tail.
- MLPerf Inference, MLCommons — <https://mlcommons.org/benchmarks/inference-datacenter/>. The project page defines the scenarios (SingleStream, MultiStream, Server, Offline) and the loadgen behavior the reference above adapts. The MLPerf Inference policy and submission rules documents (linked from the project page) formalize the warm-up, accuracy-gating, and compliance conventions that any MLPerf-style benchmark should mirror.

<!-- Local exercise context: the Server-at-20-QPS target, the 500 ms p99 SLO, the 1 × H100 SXM 80 GB SUT, the `pairwise-v2` judge at threshold 0.75, and the `bench_shapes_v2` dataset slice are illustrative defaults for a chat-serving benchmark. Replace the target QPS, SLO, GPU, judge, threshold, and shape mix with your product's own serving profile before adopting. The SLO referenced here (`SLO-PERF-01`) is defined in [exercise-01](../exercise-01-offline-regression-suite-with-gates/SOLUTION.md); the production latency dashboard that visualizes `eval:request_p95_ms` and is the live counterpart to this benchmark is in [exercise-05](../exercise-05-production-eval-observability-integration/SOLUTION.md); the shadow-launch comparison used alongside this benchmark to validate the candidate under real traffic is in [exercise-02](../exercise-02-shadow-launch-comparison/SOLUTION.md). -->
