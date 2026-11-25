# exercise-05 — Production Eval Observability Integration — Solution

## 1. Solution overview

An eval system that writes to a nightly report is an eval system that notices regressions on day two, not minute two. Production evaluation is a **running signal** — a stream of per-request judge verdicts, slice tags, latencies, refusal flags, and cost numbers — and it must live in the same observability surface that already tells the team the request router has stopped, the GPUs are saturated, and the retrieval index is drifting. If eval metrics live on one dashboard and SRE SLOs live on another, no one looks at both in an incident.

The reference solution wires three observability layers to the eval plane:

- **Metrics** — OpenTelemetry metric exporters publish per-request counters, histograms, and gauges to a Prometheus-compatible store. SLOs and SLO burn-rate alerts are expressed as Prometheus recording and alerting rules.
- **Traces** — Every scored request carries an OpenTelemetry trace context from the ingress through the model call, the judge, and the eval writer. The judge verdict is an attribute on the model-call span; the slice tags are span attributes; the shadow pair id is a baggage item that links two traces.
- **Logs** — Per-event structured JSON logs land in the log pipeline with the same `trace_id` and `span_id` that appear in the traces. Logs are the detail; metrics are the signal; traces are the join.

The reference answer has five deliverables:

1. A **telemetry conventions doc** — the committed names of metrics, span attributes, and log fields (and their semantic types). Without this, every service emits its own `quality_score` or `qualityScore` and the dashboards never agree.
2. An **OpenTelemetry SDK integration** (Python) that emits the per-request metrics, traces, and logs with the committed names.
3. A **Prometheus rules file** — recording rules that roll per-request histograms into per-slice p50/p95/p99 and SLO burn-rate alerts that fire on fast (1 h) and slow (6 h) windows.
4. A **Grafana dashboard JSON** — a committed dashboard definition with the panels an on-call person reads first: quality delta, refusal rate, p95 latency, dollars per 1k requests, slice heatmap.
5. An **alerting runbook** — one entry per alert, naming the metric, the threshold, the first-touch action, and the escalation path.

This maps directly to the NIST AI RMF `MEASURE` and `MANAGE` functions: `MEASURE` requires metrics to be "continuously monitored, in the operational context," and `MANAGE` requires alert-to-owner routes and documented responses ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML09 Output Integrity Attacks** (a silent judge or exporter outage hides a regression — a dead signal looks the same as a flat one on the chart) and **ML05 Model Theft** (observability sinks are a privileged egress that adversaries will target; the eval sink that logs full prompts is the fat target) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0043 Craft Adversarial Data` names the specific case of an attacker using a slow probe to drift a metric past a static threshold; multi-window burn-rate alerts are the direct control ([MITRE ATLAS](https://atlas.mitre.org/)).

The OpenTelemetry conventions and Prometheus recording-and-alerting semantics used below are the project standards; the specific naming is a committed project choice that should match your platform's existing conventions where present.

## 2. Worked implementation

### 2.1 Telemetry conventions (`docs/telemetry.md`)

Every exporter in the stack emits the **same names**. Choose once, write down, enforce.

```markdown
# Eval telemetry conventions (v1)

## Metrics (OpenTelemetry → Prometheus)
- `eval.request.total`              counter   labels: service, model, slice.lang, slice.intent
- `eval.request.latency_ms`         histogram labels: service, model
- `eval.request.tokens_out`         histogram labels: service, model
- `eval.request.dollars`            histogram labels: service, model
- `eval.judge.verdict.total`        counter   labels: service, model, verdict (good|bad|tie|invalid)
- `eval.judge.score`                histogram labels: service, model, slice.lang, slice.intent
- `eval.refusal.total`              counter   labels: service, model, answerable
- `eval.shadow.drop.total`          counter   labels: service, reason
- `eval.exporter.up`                gauge     (always 1 while running; staleness = outage)

## Trace attributes
- span.name = "model.call" / "judge.score" / "eval.write"
- model.id, model.build_sha, eval.slice.lang, eval.slice.intent
- eval.verdict, eval.score, eval.refusal, eval.pair_id
- shadow.arm = "incumbent" | "candidate" (only for shadow traces)

## Log fields (JSON)
- ts, level, logger, trace_id, span_id, request_id, user_id_hash
- eval.verdict, eval.score, eval.slice.*, eval.refusal
- do NOT log raw prompt / output text; log prompt_sha256 / output_sha256
```

Rules the conventions enforce:

- **One name per thing.** `eval.judge.score` is the histogram; nothing is also called `eval_judge_score` or `judge_score_pct`. A lint hook greps the codebase for forbidden alternates.
- **Label cardinality is bounded.** `slice.lang` and `slice.intent` are closed sets from `slices.yaml` (same file [exercise-01](../exercise-01-offline-regression-suite-with-gates/SOLUTION.md) uses). A free-form user id as a Prometheus label is forbidden — label cardinality explosion will quietly OOM the store.
- **Hashes, not text, in logs.** `prompt_sha256` is in the log; the raw prompt is not. The hash is the join key; the text lives in the privacy-redacted shadow log with its own ACL.
- **`eval.exporter.up` is always-emit.** A dead exporter looks the same as a flat metric. An always-emit gauge turns silence into a visible stale signal.

### 2.2 OpenTelemetry integration (`eval_otel.py`)

```python
"""Per-request eval instrumentation using the OpenTelemetry SDK.

Usage:
    from eval_otel import init, record_eval
    init(service_name="chat-serving")

    with eval_span("model.call", model_id="llm-v7", slice_tags=tags) as span:
        output = model.run(prompt)
        span.set_attribute("eval.tokens_out", output.tokens_out)

    verdict = judge.score(prompt, output)
    record_eval(
        request_id=req_id, model_id="llm-v7", slice_tags=tags,
        latency_ms=latency, tokens_out=output.tokens_out,
        dollars=cost, verdict=verdict.label, score=verdict.score,
        refusal=verdict.refusal, answerable=tags.get("answerable", True),
    )
"""

from __future__ import annotations
import contextlib
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

_initialized = False
_tracer = None
_meter = None
_m: dict = {}


def init(service_name: str, otlp_endpoint: str = "localhost:4317") -> None:
    global _initialized, _tracer, _meter, _m
    if _initialized:
        return
    resource = Resource.create({"service.name": service_name})
    # Traces
    tp = TracerProvider(resource=resource)
    tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
    trace.set_tracer_provider(tp)
    _tracer = trace.get_tracer("eval")
    # Metrics
    reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=otlp_endpoint))
    mp = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(mp)
    _meter = metrics.get_meter("eval")
    _m["request_total"] = _meter.create_counter("eval.request.total")
    _m["latency_ms"] = _meter.create_histogram("eval.request.latency_ms")
    _m["tokens_out"] = _meter.create_histogram("eval.request.tokens_out")
    _m["dollars"] = _meter.create_histogram("eval.request.dollars")
    _m["verdict_total"] = _meter.create_counter("eval.judge.verdict.total")
    _m["judge_score"] = _meter.create_histogram("eval.judge.score")
    _m["refusal_total"] = _meter.create_counter("eval.refusal.total")
    _m["exporter_up"] = _meter.create_up_down_counter("eval.exporter.up")
    _m["exporter_up"].add(1)
    _initialized = True


def _slice_labels(tags: dict) -> dict:
    return {
        "slice.lang": tags.get("lang", "unknown"),
        "slice.intent": tags.get("intent", "unknown"),
    }


@contextlib.contextmanager
def eval_span(name: str, *, model_id: str, slice_tags: dict):
    with _tracer.start_as_current_span(name) as span:
        span.set_attribute("model.id", model_id)
        for k, v in _slice_labels(slice_tags).items():
            span.set_attribute(k.replace("slice.", "eval.slice."), v)
        yield span


def record_eval(
    *, request_id: str, model_id: str, slice_tags: dict,
    latency_ms: float, tokens_out: int, dollars: float,
    verdict: str, score: float, refusal: bool, answerable: bool,
) -> None:
    labels = {"service": "chat-serving", "model": model_id, **_slice_labels(slice_tags)}
    _m["request_total"].add(1, labels)
    _m["latency_ms"].record(latency_ms, {"service": labels["service"], "model": model_id})
    _m["tokens_out"].record(tokens_out, {"service": labels["service"], "model": model_id})
    _m["dollars"].record(dollars, {"service": labels["service"], "model": model_id})
    _m["judge_score"].record(score, labels)
    _m["verdict_total"].add(1, {**labels, "verdict": verdict})
    if refusal:
        _m["refusal_total"].add(1, {"service": labels["service"], "model": model_id,
                                     "answerable": str(bool(answerable)).lower()})
```

Design rules worth calling out:

- **Labels are bounded and documented.** No `user_id`, no `request_id` on metrics. Those are on logs and spans only.
- **Histograms for durations and sizes, counters for events.** Prometheus histogram buckets must be committed (see §2.3); a dashboard that reads `p95` on a wrong bucket config is misleading.
- **Context is propagated.** `eval_span` sets the `trace_id` the logger will pick up; the log line that records `verdict=bad` carries the same `trace_id` as the span it came from, which is how a reviewer jumps from a chart to the request.
- **Exporter up-signal.** `eval.exporter.up` starts at 1 and stays there; its absence in Prometheus (`absent(eval_exporter_up)`) is the alert that the exporter died.

### 2.3 Prometheus rules (`rules/eval.yml`)

Two kinds of rules: **recording rules** that pre-aggregate per-slice p-quantiles once per minute (so dashboards query a cheap time series, not the raw histogram), and **alerting rules** that trip on multi-window burn rates.

```yaml
# rules/eval.yml
groups:
  - name: eval.recording
    interval: 1m
    rules:
      - record: eval:request_p50_ms:rate5m
        expr: histogram_quantile(0.50, sum by (le, model, slice_lang) (rate(eval_request_latency_ms_bucket[5m])))
      - record: eval:request_p95_ms:rate5m
        expr: histogram_quantile(0.95, sum by (le, model, slice_lang) (rate(eval_request_latency_ms_bucket[5m])))
      - record: eval:refusal_rate:rate5m
        expr: sum by (model) (rate(eval_refusal_total{answerable="true"}[5m])) / sum by (model) (rate(eval_request_total[5m]))
      - record: eval:verdict_bad_rate:rate5m
        expr: sum by (model) (rate(eval_judge_verdict_total{verdict="bad"}[5m])) / sum by (model) (rate(eval_request_total[5m]))
      - record: eval:cost_per_1k:rate5m
        expr: 1000 * sum by (model) (rate(eval_request_dollars_sum[5m])) / sum by (model) (rate(eval_request_total[5m]))

  - name: eval.alerts
    rules:
      - alert: EvalExporterDown
        expr: absent(eval_exporter_up) or avg_over_time(eval_exporter_up[5m]) < 1
        for: 2m
        labels: { severity: page, service: chat-serving }
        annotations:
          summary: "eval exporter is not reporting"
          runbook: "runbooks/eval_exporter_down.md"

      - alert: QualityBurnRateFast
        # Fast window: 2% error budget burn in 1h and the same in 5m (short-term pulse)
        expr: |
          (eval:verdict_bad_rate:rate5m > (14.4 * 0.01))
          and
          (avg_over_time(eval:verdict_bad_rate:rate5m[1h]) > (14.4 * 0.01))
        for: 2m
        labels: { severity: page, service: chat-serving, slo: SLO-QUALITY-02 }
        annotations:
          summary: "verdict=bad burn rate 14.4x over SLO (fast window)"
          runbook: "runbooks/quality_burn_rate.md"

      - alert: QualityBurnRateSlow
        # Slow window: 10% error budget burn in 6h (catches chronic drift)
        expr: |
          (eval:verdict_bad_rate:rate5m > (6 * 0.01))
          and
          (avg_over_time(eval:verdict_bad_rate:rate5m[6h]) > (6 * 0.01))
        for: 15m
        labels: { severity: ticket, service: chat-serving, slo: SLO-QUALITY-02 }
        annotations:
          summary: "verdict=bad burn rate 6x over SLO (slow window)"
          runbook: "runbooks/quality_burn_rate.md"

      - alert: RefusalRateOverCeiling
        expr: eval:refusal_rate:rate5m > 0.02
        for: 10m
        labels: { severity: ticket, service: chat-serving, slo: SLO-UX-01 }
        annotations:
          summary: "refusal rate on answerable items > 2% for 10m"
          runbook: "runbooks/refusal_rate_over_ceiling.md"

      - alert: LatencyP95OverCeiling
        expr: eval:request_p95_ms:rate5m{model="llm-v7"} > 300
        for: 10m
        labels: { severity: page, service: chat-serving, slo: SLO-PERF-01 }
        annotations:
          summary: "p95 latency over SLO ceiling (300 ms) for 10m"
          runbook: "runbooks/latency_p95.md"

      - alert: ShadowDropsSustained
        expr: sum by (service) (rate(eval_shadow_drop_total[10m])) > 0.05
        for: 15m
        labels: { severity: ticket, service: chat-serving }
        annotations:
          summary: "shadow drop rate >5% for 15m"
          runbook: "runbooks/shadow_drops.md"
```

Rules of the ruleset:

- **Multi-window burn-rate** alerts fire on a fast and a slow window pair (a standard SRE pattern for SLO burn-rate alerting). A single-window alert on the fast series is too noisy; a single slow window is too slow to catch an acute regression.
- **Error-budget base rate matches the SLO.** The `0.01` in `QualityBurnRate*` is the SLO budget (`verdict=bad` ≤ 1%). The `14.4x` multiplier is the standard constant that corresponds to burning 2% of a 30-day budget in 1 h.
- **Histogram quantile over `_bucket`, not `avg`.** `histogram_quantile(0.95, sum by (le) (rate(..._bucket[5m])))` is the Prometheus-correct form; averaging `_sum / _count` returns a mean, not a p95.
- **One label per thing**, closed-set. A rule that aggregates over `model`, `slice_lang` is cheap; a rule that aggregates over `user_id` will OOM the recording layer.

### 2.4 Grafana dashboard (`dashboards/eval_production.json` — panels)

The dashboard is a committed JSON (not screenshotted into a wiki). The first row contains five panels:

1. **Quality delta (per model)** — `eval:verdict_bad_rate:rate5m`, one line per `model`, with an SLO reference line at 1%.
2. **Refusal rate (answerable)** — `eval:refusal_rate:rate5m`, SLO line at 2%.
3. **p95 latency (per model)** — `eval:request_p95_ms:rate5m`, SLO line at 300 ms.
4. **Dollars per 1k requests** — `eval:cost_per_1k:rate5m`, budget line at the committed per-1k ceiling.
5. **Slice heatmap** — `verdict=bad` rate by `slice_intent × slice_lang`, 5-minute cells, color stops at 1% / 2% / 5%.

The second row:

6. **Exporter up** — `eval_exporter_up`, red when below 1 at any time in window.
7. **Shadow drop rate** — `rate(eval_shadow_drop_total[5m])`, with top-N by `reason`.
8. **Verdict breakdown** — stacked: good / bad / tie / invalid as fractions of total.

Rules:

- **SLO lines on every quality / latency / cost panel.** A chart without the ceiling is a mood chart.
- **Dashboard JSON committed.** A mutable dashboard is a lost dashboard; a committed JSON reviewed via PR survives reorgs.
- **Default time range is 24 h, with a 7-d link.** Alert triage lives in the last 24 h; week-over-week drift is a separate link.
- **No per-user panels.** A per-user dashboard fed by a Prometheus label is both a cardinality bomb and a privacy surface. Per-user investigations happen via traces/logs, not metrics.

### 2.5 Runbooks (`runbooks/`)

Every alert has a runbook. The runbook is short on purpose.

```markdown
# Runbook: QualityBurnRateFast

**Alert:** eval:verdict_bad_rate burning 14.4× the SLO in 1h window.
**SLO:** SLO-QUALITY-02 (verdict=bad ≤ 1%).
**Owner:** model-eval@team (page).

## First-touch (within 15 min)
1. Open the Grafana "Eval Production" dashboard, 2h window.
2. Confirm the signal is in `verdict=bad`, not in `invalid` (which usually means a judge outage).
3. Check the slice heatmap. If the signal is one slice, go to step 5; if broad, step 4.
4. **Broad signal:** check `eval:request_p95_ms`, `eval_shadow_drop_total`, and router error rate. A broad quality regression that lines up with a router error spike is a routing bug, not a model regression.
5. **Narrow signal:** pull 20 bad-verdict traces (`service=chat-serving, eval.verdict=bad, slice.intent=<X>`). Open five. If retrieval is involved, inspect the retrieved doc ids.

## Mitigate
- If the newest build is the cause: roll back to the previous `model.build_sha`.
- If a retrieval index change is the cause: roll back the index to the prior pin.

## Escalation (if no diagnosis in 45 min)
- Page: on-call-infra@team if router or GPU saturation suspected.
- Page: trust-safety@team if the bad-verdict content is policy-adjacent.
```

Rules the runbook obeys:

- **The runbook is the first-touch**, not a complete causal graph. Three steps max for triage.
- **Rollback is named.** The specific CLI or dashboard button for "roll back to previous `model.build_sha`" is linked.
- **Escalation is named with a real owner.** Not "infra"; the specific team or on-call.
- **The runbook is edited after every alert postmortem.** A runbook that never changes is a runbook nobody uses.

### 2.6 Privacy and safety of the sinks

- **Logs do not carry raw prompt / output text.** Only hashes. The ACL on the privileged shadow / trace store is tighter than the ACL on the Prometheus / Grafana store.
- **Traces store sanitized attributes.** Free-form user prompts never land on a span attribute.
- **Retention is short.** Prometheus retention is weeks; traces are days; the privileged shadow log is weeks with an owner-controlled override.
- **Egress is audited.** Who read the trace store yesterday is in an audit log. The `eval.exporter.up` gauge has a sibling `eval.export.auth.failed` counter whose non-zero value fires its own alert.

These map to OWASP ML Top 10 **ML04 Membership Inference Attack** (user-identifying attributes on logs are a surface) and **ML05 Model Theft** (the trace store, if externally queryable, is a scraping target).

## 3. Validation steps

1. **Convention lint.** CI greps for the forbidden alternates (`qualityScore`, `quality_pct`, `user_id` as a metric label); the lint fails on a hit.
2. **Metric-span-log join.** A synthetic request produces a span, a metric point, and a log line. The log's `trace_id` matches the span's `trace_id`; the metric's labels are the committed set.
3. **Histogram quantile correctness.** Fire 1000 requests at known latencies; `histogram_quantile(0.95, ...)` returns the expected bucket; `histogram_quantile(0.99, ...)` likewise.
4. **Burn-rate alert fires on a step change.** A chaos test injects a 20% `verdict=bad` rate; `QualityBurnRateFast` fires within the configured `for:` window (≤ 2 m).
5. **Exporter-down alert fires on absence.** Kill the exporter; `EvalExporterDown` fires within 5 m. Restart; it resolves.
6. **Cardinality cap.** A test injects a free-form label value on `eval.request.total`; the cardinality guard rejects the write and logs the violation.
7. **Dashboard JSON round-trip.** A commit that edits the dashboard via UI diffs `dashboards/eval_production.json`; CI fails if the committed file does not match the UI state.
8. **Runbook coverage.** For every alert in `rules/eval.yml`, a `runbooks/<name>.md` exists; CI fails otherwise.
9. **Slice-label parity.** `slice.lang` and `slice.intent` emitted by the exporter are a subset of the closed set in `slices.yaml`; a test fires with an unknown slice and asserts the exporter defaults it to `"unknown"` rather than passing it through.
10. **Privacy audit.** A random 100-log sample has no `prompt_text`, `output_text`, or user-identifying attributes; `prompt_sha256` and `output_sha256` are present.
11. **Deterministic rules.** The recording-rule expressions produce the same time series on two replays of the same input stream (within Prometheus's scrape-interval resolution).

## 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Committed telemetry conventions with bounded label set | 1 | `docs/telemetry.md` names all metrics, spans, logs; lint enforces. |
| R2 | OpenTelemetry integration emits metrics, spans, and logs with the committed names | 1 | `eval_otel.py` plus a synthetic-request test that round-trips. |
| R3 | Exporter-up gauge with an absence alert | 1 | `eval.exporter.up` metric; `EvalExporterDown` alert; chaos test. |
| R4 | Prometheus recording rules for per-slice p95 / refusal / cost / verdict | 1 | `rules/eval.yml` recording section. |
| R5 | Multi-window SLO burn-rate alerts (fast + slow) | 2 | Burn-rate pair for at least one SLO; chaos test fires the fast alert. |
| R6 | Grafana dashboard committed as JSON with SLO reference lines | 1 | `dashboards/eval_production.json`; panels for quality, refusal, p95, cost, slice heatmap. |
| R7 | Runbook per alert, naming first-touch, rollback, escalation | 1 | `runbooks/<alert>.md` for every alert; CI checks coverage. |
| R8 | Logs carry hashes, not raw text; closed-set slice labels | 1 | Privacy audit test; cardinality lint. |
| R9 | Manifest / README pins versions (OTel SDK, Prometheus rules commit, dashboard JSON commit) | 1 | Versions pinned; rerun identifies the same artifact set. |

**Passing bar:** 7 / 10. R3 and R5 are non-negotiable — a dashboard without an exporter-up alert cannot distinguish "all fine" from "silent"; a single-window alert is either too noisy or too slow.

Reviewer checklist:

- [ ] Telemetry conventions file exists and the lint runs in CI.
- [ ] `eval.exporter.up` emitted; `EvalExporterDown` alert covers absence.
- [ ] Recording rules for p95 / refusal / cost / verdict are present and non-expensive.
- [ ] At least one multi-window burn-rate alert exists and has been fired in a chaos test.
- [ ] Grafana dashboard JSON is committed and has SLO reference lines.
- [ ] Every alert has a runbook with first-touch, rollback, and escalation.
- [ ] No raw prompt / output text on logs or spans; hashes present.
- [ ] Slice labels are closed-set.

## 5. Common mistakes

- **Averaging a histogram.** `avg(eval_request_latency_ms_sum) / avg(eval_request_latency_ms_count)` returns a mean; the chart will show a reasonable number while the real p95 is burning. Use `histogram_quantile(..., sum by (le) (rate(..._bucket[...])))`.
- **Unbounded labels.** `user_id` or `request_id` as Prometheus labels will OOM the store within hours. Keep labels to a closed set; put the high-cardinality ids on traces/logs.
- **Single-window alerts.** A 5-minute rate-above-threshold alert flaps on normal noise; a 24-hour one notices too late. Use fast+slow burn-rate pairs.
- **Missing exporter-up alert.** The Prometheus side cannot tell a dead exporter from a quiet signal. `absent(...)` on an always-emit gauge is the direct control.
- **Dashboards edited by UI, not JSON.** A reorg or workspace reset loses them; a reviewer six months later cannot reconstruct the intended view. Commit the JSON.
- **Alerts without runbooks.** An on-call who gets paged with no runbook invents a response; the next on-call invents a different one. Commit a runbook per alert.
- **Raw prompt text on logs.** The logs become a privacy artifact and a scraping target. Hashes only; raw text lives in the privileged shadow log with its own ACL.
- **Mixed metric naming.** `judge_score` in one service, `eval_judge_score` in another: no dashboard works across services. The conventions doc + lint prevents this.
- **One monolithic alert for "the eval is bad."** A single alert that triggers on any of {quality, latency, refusal, cost} merges the on-call's triage. Split per SLO.
- **Burn-rate base rate pulled from the ruleset instead of the SLO.** The budget constant must match the SLO (`0.01` for a 1% SLO). A mismatch hides acute regressions.
- **Dropping `tie` and `invalid` verdicts from the metric.** `invalid` is the judge-outage signal; dropping it hides judge outages. Count every verdict; alert specifically on `invalid` spikes.
- **No chaos test for alerts.** An alert that has never been shown to fire is an alert of unknown functionality. The quarterly fire-drill is in CI.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. `MEASURE` calls for continuous monitoring in the operational context; the OpenTelemetry integration, the committed metric names, and the SLO-linked burn-rate alerts are the direct operationalization. `MANAGE` calls for alert-to-owner routes and documented responses; runbooks fulfill this.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML04 Membership Inference Attack** motivates logging hashes not text; **ML05 Model Theft** motivates ACLs and audited egress on the trace store; **ML09 Output Integrity Attacks** motivates the multi-window burn-rate design — a static threshold is a weak detector for an adversary who drifts the input.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0043 Craft Adversarial Data` names the slow-drift attack; multi-window alerts are the control. The `eval.exporter.up` gauge addresses the detection-availability leg of `AML.T0015 Evade ML Model`.

<!-- Local exercise context: the metric names (`eval.request.total`, `eval.judge.score`), the SLO base rate (1% bad verdicts), the burn-rate multipliers (14.4× fast, 6× slow over a 30-day budget), the 300 ms p95 ceiling, and the 2% refusal ceiling are illustrative defaults for a chat product running on OpenTelemetry → Prometheus → Grafana. Replace the names, SLO base rates, and ceilings with your platform's conventions and budgets before adopting. The offline gates that define the SLOs referenced here (`SLO-QUALITY-02`, `SLO-UX-01`, `SLO-PERF-01`) are in [exercise-01](../exercise-01-offline-regression-suite-with-gates/SOLUTION.md); the shadow log that feeds `eval_shadow_drop_total` is in [exercise-02](../exercise-02-shadow-launch-comparison/SOLUTION.md); the sequential-test monitor whose `stop_*` events drive the `stop_efficacy` and `stop_futility` dashboards is in [exercise-04](../exercise-04-sequential-testing-for-continuous-monitoring/SOLUTION.md); the latency SLO measured by `eval:request_p95_ms:rate5m` is validated by the serving benchmark in [exercise-06](../exercise-06-mlperf-style-serving-benchmark/SOLUTION.md). -->
