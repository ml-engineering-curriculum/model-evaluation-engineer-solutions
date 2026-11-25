# exercise-02 — Shadow-Launch Comparison on Non-IID Traffic — Solution

## 1. Solution overview

A shadow launch sends live production traffic to a **candidate** model in parallel with the serving incumbent, scores both, and compares them — without the candidate's output ever reaching a user. It is the only way to see how a candidate behaves on the exact distribution the incumbent sees: the current time-of-day mix, the current prompt lengths, the current rate of empty inputs, the current churn in topics. An offline eval set, however carefully built, is IID with respect to its own creation date, not with respect to production at 03:00 UTC on a holiday.

The naïve shadow is simple — duplicate the request, log both outputs — and nearly always wrong. Production traffic is **non-IID in the ways that matter for comparison**:

- Diurnal cycles and event storms shift the slice mix minute-to-minute.
- Request pairs are not independent: a single user often produces a burst of related requests.
- Costly or long tool calls are not uniformly distributed; a shadow that samples without stratifying will undersample them.
- A candidate that is faster on simple queries and slower on the heavy 1% of queries will look faster in aggregate until a holiday surfaces the 1%.

The reference solution is a **paired-sample shadow** that captures request, incumbent response, candidate response, and judge verdict on the same request id, stratifies the sampling and the analysis by slice, bootstraps paired differences, and reports with confidence intervals that account for the non-IID structure. The deliverable is a committed replay log that an engineer can re-score months later.

The reference answer has five deliverables:

1. A **shadow plane design** — where the fork happens, what budget it has, and the write path for `shadow_events.jsonl`.
2. A **paired event schema** — one record per request with both outputs, slice tags, and an incumbent-only `serving_outcome`.
3. A **stratified sampler** — sampling rates per slice with committed floors so under-represented slices do not disappear.
4. A **paired-difference analyzer** — bootstrap or sign-test on paired deltas, clustered by user, per slice.
5. A **shadow report** — per-slice win/loss/tie with CIs, plus a cost-and-latency ledger that separates candidate-vs-incumbent compute.

This maps to the NIST AI RMF `MEASURE` function, which requires evaluations to be "repeatable, with documented tools and assumptions," and `MANAGE`, which asks that pre-deployment risk decisions be recorded with a defined operational context ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML05 Model Theft** (a shadow endpoint that is queryable from outside the privileged plane is a model-extraction surface), **ML04 Membership Inference Attack** (logging the paired outputs widely is a surface), and **ML09 Output Integrity Attacks** (a candidate that has access to a side channel — logs, timing — the incumbent lacks is cheating on the shadow) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS techniques `AML.T0040 ML Model Inference API Access` and `AML.T0043 Craft Adversarial Data` describe the specific risks of standing up a candidate endpoint fed by live traffic ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Where the fork happens

The fork point is a design decision with three real choices; the solution pins one and records why.

```
                       +---------+       user response
     user request ---> | router  |-----------------------+
                       +----+----+                       |
                            | fork (dup, async)          |
                            v                            |
                       +----+----+                       |
                       | shadow  |--+  incumbent_output  |
                       | runner  |  +---------------------+
                       +----+----+
                            |
                            v
                       +----+----+
                       |candidate|
                       | model   |
                       +----+----+
                            |
                            v
                    shadow_events.jsonl
                    (incumbent + candidate + judge)
```

Three rules the fork obeys:

- **Candidate never affects the user response.** The router returns the incumbent's output and the shadow runner is asynchronous. A shadow that blocks on the candidate turns a regression in the candidate into a user-visible latency event.
- **Budget on the shadow is distinct from serving.** The candidate has its own token / dollar / wall-clock budget; when the shadow queue is saturated, the shadow runner drops requests (and records the drop) rather than back-pressuring the serving path.
- **Parity of context.** The candidate receives the same prompt, system message, tool catalog, and feature flags the incumbent received for *that request*. Any diff — a newer tool catalog, a different retrieval index — is a confound and must be committed on the manifest or the shadow is invalid.

### 2.2 Paired event schema

One JSON line per request in `shadow_events.jsonl`:

```json
{
  "shadow_event_id": "se-2026-11-20-00000142",
  "request_id": "req-9f4a...",
  "user_id_hash": "u-8c1...",
  "request_ts": "2026-11-20T14:05:11.837Z",
  "slice_tags": ["lang:en", "intent:billing", "tenure:new_user", "hour:14"],
  "request": {
    "prompt_sha256": "<sha of normalized prompt>",
    "prompt_tokens": 412,
    "tools_available_version": "tools-v7",
    "flags": {"feature-x": "on"}
  },
  "incumbent": {
    "model_id": "product-llm-v6",
    "output_sha256": "<sha>",
    "output_text": null,              // may be redacted; see §2.6
    "tokens_in": 412, "tokens_out": 58, "dollars": 0.0032,
    "latency_ms": 184
  },
  "candidate": {
    "model_id": "product-llm-v7-candidate",
    "output_sha256": "<sha>",
    "output_text": null,
    "tokens_in": 412, "tokens_out": 61, "dollars": 0.0029,
    "latency_ms": 167,
    "sampled_reason": "stratified(lang:en,intent:billing)"
  },
  "serving_outcome": {
    "user_turned_over": false,
    "clicked_link": null,
    "latency_seen_by_user_ms": 184
  },
  "judge": {
    "name": "pairwise-v2",
    "verdict": "candidate_better",    // {candidate_better, incumbent_better, tie, invalid}
    "confidence": 0.78,
    "ran_at": "2026-11-20T14:05:17.420Z"
  }
}
```

Four invariants to enforce in CI:

- Every row has both `incumbent` and `candidate`; a row with a missing side is a leak between the two paths and is not comparable. Dropped candidate requests go to a **separate** `shadow_drops.jsonl`.
- `serving_outcome` applies to the incumbent only. Attributing `clicked_link` to the candidate would require the candidate to have served the user — exactly what a shadow cannot do.
- `slice_tags` come from the same closed-set taxonomy that `exercise-01` uses; comparison slices are a property of the eval regime, not the shadow.
- `prompt_sha256` and `output_sha256` are always present; the text may be redacted at rest depending on the privacy posture (see §2.6), but the hash makes equality of two prompts detectable without the text.

### 2.3 Stratified sampler

A raw 10% sample is biased by whatever cohort overproduces requests — in most products, a handful of heavy users. A stratified sampler guarantees per-slice coverage:

```python
"""Stratified shadow sampler.

Each slice has a committed per-second budget and a minimum per-hour floor.
When the budget is exhausted the request goes to the incumbent only; when
the floor has not been met in the last hour the sampler shifts probability
toward the under-sampled slices so the paired analysis has power on every
slice, not just the modal one."""

from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class SliceBudget:
    name: str
    tag: str
    per_second_cap: float      # expected shadow QPS for this slice
    per_hour_floor: int        # minimum requests to collect per hour


def _stable_bucket(key: str) -> float:
    """Deterministic, user-stable 0..1 bucket. The same user_id maps to the
    same bucket in the same hour, which prevents user-churn artifacts where
    a heavy user is 'half-in' the shadow."""
    h = hashlib.blake2b(key.encode(), digest_size=8).hexdigest()
    return int(h, 16) / 2**64


def should_shadow(
    request, slice_budgets, counters, now_s: float, hour_bucket: int
) -> tuple[bool, str]:
    tag = _pick_primary_slice(request, slice_budgets)
    if tag is None:
        return False, "no_slice"
    budget = slice_budgets[tag]
    bucket = _stable_bucket(f"{request['user_id_hash']}:{hour_bucket}")
    # Default rate scaled by the budget divided by the observed slice QPS.
    observed_qps = counters.observed_qps_for(tag)
    base_rate = min(1.0, budget.per_second_cap / max(observed_qps, 1e-9))
    # Boost the rate if the hourly floor has not been met.
    collected_this_hour = counters.collected_for(tag, hour_bucket)
    if collected_this_hour < budget.per_hour_floor:
        base_rate = max(base_rate, 2 * base_rate)   # halve the headroom gap
    return (bucket < base_rate), f"stratified({tag},rate={base_rate:.3f})"
```

Rules:

- **User-stable buckets.** Two requests from the same user in the same hour are both in or both out of the shadow. Mixing them makes paired analysis within-user invalid (see §2.4).
- **Per-slice floor.** A slice below its floor has the sampling probability boosted — the shadow is not useful if the long-tail slice never fills.
- **Sampling reason is recorded.** `candidate.sampled_reason` names the rule that let the event in. A reviewer six months later needs the sampler's rule to reconstruct why a slice has 2× the mass of another.

### 2.4 Paired-difference analysis

Shadow comparison is a **paired** problem: for each request we have two outputs. The analysis exploits the pairing and clusters by user.

Primary estimator:

```python
"""Per-slice paired comparison.

For each slice:
- score_i = 1 (candidate better), 0 (tie or invalid), -1 (incumbent better).
- estimator: mean(score) with a user-clustered bootstrap for the CI.
"""

from __future__ import annotations
import numpy as np


def _code_verdict(v: str) -> int:
    return {"candidate_better": 1, "incumbent_better": -1, "tie": 0, "invalid": 0}[v]


def paired_mean_with_user_clustered_ci(events, iters=1000, seed=20261120) -> dict:
    rng = np.random.default_rng(seed)
    if not events:
        return {"point": None, "ci_lo": None, "ci_hi": None, "n": 0, "n_users": 0}
    # Group codes by user_id_hash; one cluster per user.
    clusters: dict[str, list[int]] = {}
    for e in events:
        clusters.setdefault(e["user_id_hash"], []).append(_code_verdict(e["judge"]["verdict"]))
    user_ids = list(clusters)
    user_means = np.array([np.mean(clusters[u]) for u in user_ids], dtype=float)
    n_users = len(user_ids)
    n = sum(len(v) for v in clusters.values())
    # Cluster bootstrap: resample USERS with replacement; within each user,
    # take the mean. This gives honest CIs under within-user correlation.
    idx = rng.integers(0, n_users, size=(iters, n_users))
    resample_means = user_means[idx].mean(axis=1)
    return {
        "point": float(user_means.mean()),
        "ci_lo": float(np.quantile(resample_means, 0.025)),
        "ci_hi": float(np.quantile(resample_means, 0.975)),
        "n": int(n),
        "n_users": int(n_users),
    }
```

Why this estimator:

- **Pair the scoring.** The judge scores `(incumbent_output, candidate_output)` on the *same* request. An unpaired win-rate on two independent samples throws away half the information in the shadow log.
- **Cluster by user.** Two requests from the same user share topic, style, and intent; an IID bootstrap overstates the n and understates the CI. A user-clustered bootstrap resamples users, not requests, and reports an honest interval.
- **Score domain is {-1, 0, +1}.** The sign-coded score is appropriate for pairwise verdicts. Reporting as a win-rate (fraction `candidate_better`) is equivalent to `(mean+1)/2` and should be reported alongside; both are a function of the same per-event verdict.
- **A `tie` or `invalid` is a zero, not a drop.** Dropping ties inflates both win and loss rates by the same factor and loses the "no measurable difference" signal — which is often the correct verdict.

For slice-mix robustness (candidate is better on a slice that happened to be over-sampled this week), report:

- **Per-slice `mean, n, n_users, CI`** (never aggregate without the slice table).
- **Aggregate** as the mean of per-slice means weighted by the *production* slice mix, not the shadow mix. Weights come from a committed `production_slice_weights.yaml` derived from the last 28 days of serving logs.

### 2.5 Report and manifest

`shadow_report_<run_id>.md` opens with the table a reviewer reads first:

```markdown
# Shadow run shadow_2026-11-20 (14 d, 2026-11-06 → 2026-11-20)

| Slice | n_pairs | n_users | Candidate win rate | Mean paired score (CI) | Verdict |
|---|---|---|---|---|---|
| lang_en | 184_312 | 42_118 | 0.521 | +0.041 [+0.035, +0.047] | candidate ↑ |
| lang_es | 21_908 | 7_422 | 0.498 | -0.004 [-0.013, +0.006] | tie |
| intent_billing | 11_204 | 3_801 | 0.447 | -0.106 [-0.124, -0.088] | candidate ↓ (blocks) |
| new_user_first_7d | 29_770 | 12_017 | 0.515 | +0.030 [+0.020, +0.040] | candidate ↑ |

### Production-weighted aggregate (weights: 28d prod mix)
+0.018 [+0.012, +0.024]    (candidate overall slightly better; one slice regresses)

### Cost ledger
| | Mean tokens_out | Mean dollars | p95 latency_ms |
|---|---|---|---|
| Incumbent  | 61 | 0.0028 | 310 |
| Candidate  | 69 | 0.0031 | 285 |
```

The **per-slice table comes first and the aggregate is last**, exactly inverted from the order a team will be tempted to display. A reviewer skims the first table and sees the billing regression; a reviewer who sees only the aggregate ships the candidate.

Manifest `shadow_run.yaml`:

```yaml
run_id: shadow_2026-11-20
window:
  start: 2026-11-06T00:00:00Z
  end:   2026-11-20T00:00:00Z
incumbent:
  model_id: product-llm-v6
  build_sha: <git sha>
candidate:
  model_id: product-llm-v7-candidate
  build_sha: <git sha>
fork_point: router v4
sampler:
  config_sha: <sha256 of sampler config>
  per_slice_budgets_yaml: shadow/sampler.yaml
judge:
  name: pairwise-v2
  version: 2.3.1
  temperature: 0.0
  seed: 20261120
analysis:
  bootstrap:
    iters: 1000
    seed: 20261120
    cluster_key: user_id_hash
  slice_weights:
    file: shadow/production_slice_weights.yaml
    derivation_window_days: 28
privacy:
  text_at_rest: redacted
  hashed_fields: [prompt, output]
  retention_days: 30
```

### 2.6 Privacy and safety of the shadow log

The shadow log contains live user text on both sides — the single densest PII artifact a production model team produces. The committed defaults:

- **Text at rest redacted** behind a short retention; hashes are kept for correlation.
- **Access on a least-privilege ACL**; the model team reviews via a privacy-aware viewer, not raw downloads.
- **Candidate output never joins user events.** A click or follow-up turn belongs to the incumbent only; attributing user behavior to the candidate is both statistically wrong (no treatment occurred) and a privacy risk (links a candidate's hypothetical output to a real user action).
- **Retention is the shortest window that supports the analysis.** 30 d covers the longest paired analysis window; longer retention is a committed exception with an owner.

This maps to the OWASP ML Top 10 **ML04 Membership Inference Attack** surface: a long-retained raw shadow log that joins user ids to model outputs is the archetype. The committed hashing and TTL are the direct controls.

## 3. Validation steps

1. **Pair integrity.** For every `shadow_event_id`, both `incumbent` and `candidate` blocks are present; a missing side rejects the event and records it in `shadow_drops.jsonl` with a reason.
2. **Context parity.** For every event, `request.tools_available_version` and `request.flags` are identical between incumbent and candidate. Divergence fails the event.
3. **Sampler determinism.** Replaying the sampler over the stream of production requests with the same config SHA produces the same `shadow_event_id` set.
4. **Slice floors met.** For every slice in `sampler.yaml`, `n_pairs` for the run window is ≥ its hourly floor × hours in window × a committed margin.
5. **Clustered bootstrap is clustered.** A test with two synthetic users — one with 10 wins, one with 10 losses — produces a wider CI than the same 20 events spread over 20 users. If the CI is the same, the clustering is broken.
6. **Verdict code semantics.** Pin the mapping (`candidate_better→+1`, `incumbent_better→-1`, `tie→0`, `invalid→0`). A change bumps the judge version and triggers a re-score.
7. **Reweighted aggregate.** The production-weighted aggregate in the report matches a recomputation from `per_slice_results.json` using `production_slice_weights.yaml`.
8. **Cost ledger reproducibility.** The per-side mean `tokens_out`, `dollars`, and p95 `latency_ms` can be recomputed from `shadow_events.jsonl` alone; the ledger is a rendering, not a separate source of truth.
9. **PII redaction audit.** A random 100-event sample has `output_text=null` and `prompt_text=null` at rest; `prompt_sha256` and `output_sha256` are present and non-null.
10. **Shadow isolation.** A chaos test that fails the candidate endpoint for 10 s produces `shadow_drops` entries and **no** incumbent-serving latency events in the serving SLO dashboard.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the shadow being **a replayable, statistically honest, privacy-aware record**, not a win-rate scalar.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Shadow is asynchronous and cannot affect the user response | 2 | Chaos test shows candidate failure has zero user-visible impact. |
| R2 | Paired event schema with prompt/output hashes and slice tags | 1 | Every event has both sides, hashes, and closed-set tags. |
| R3 | Stratified sampler with per-slice budgets and hourly floors | 1 | `sampler.yaml` enforced; every slice meets its floor in the run window. |
| R4 | User-clustered bootstrap CIs on paired deltas | 2 | Synthetic test distinguishes 2-user vs 20-user data; CI width differs. |
| R5 | Per-slice table first, production-weighted aggregate last | 1 | `shadow_report.md` layout; aggregate uses committed prod weights. |
| R6 | Candidate never attributed to user behavior | 1 | `serving_outcome` applies to incumbent only; test rejects a row that tries. |
| R7 | PII redaction + ACL + short retention | 1 | Text redacted at rest; hashes kept; TTL ≤ 30 d; retention exceptions are committed. |
| R8 | Manifest pins incumbent, candidate, fork point, sampler SHA, judge, seeds, weights, window | 1 | `shadow_run.yaml` has every field; rerun produces identical event set. |

**Passing bar:** 7 / 10. R1 and R4 are non-negotiable — a shadow that affects users is not a shadow; an IID bootstrap on clustered events is a misquoted CI.

Reviewer checklist:

- [ ] Shadow runner is asynchronous; candidate failure does not page serving.
- [ ] Every event has both sides, prompt/output hashes, slice tags, and sampler reason.
- [ ] Sampler is deterministic and stratified; every slice meets its floor.
- [ ] CIs are user-clustered; test with concentrated-vs-spread users shows expected CI widening.
- [ ] Report shows per-slice table first; aggregate is production-weighted.
- [ ] `serving_outcome` is on the incumbent only.
- [ ] Text is redacted at rest; hashes present; retention ≤ 30 d.
- [ ] Manifest pins all config SHAs and versions; rerun reproduces the event set.

## 5. Common mistakes

- **Blocking fork.** Dupe-dispatch synchronously to the candidate; a slow candidate adds its tail to the user's latency. The serving path's SLO starts flapping and nobody knows why.
- **Independent samples instead of pairs.** Sampling 10% of requests for incumbent-only and 10% for candidate-only, then comparing. The paired signal is gone; small differences are drowned in between-request variance.
- **IID bootstrap on clustered data.** CI is tight, p-values are tiny, "statistically significant" claim is wrong. Cluster by user.
- **Dropping ties and `invalid`s.** Ties and invalids ARE the signal. A change that makes 20% of outputs invalid and the rest a 60/40 split for the candidate looks like "60% win rate" if you drop invalids — a textbook false ship.
- **Over-reporting the aggregate.** Leading with "candidate wins 52%" when one revenue-critical slice regresses. Per-slice table is first.
- **Non-stratified sampler.** A 10% uniform sample over-represents heavy users and under-represents the long tail. Stratify.
- **Attributing user clicks to the candidate.** The user never saw the candidate's output. Any join of `candidate.output` to `serving_outcome.click` is wrong — statistically (no treatment) and legally (data minimization violation).
- **No context parity.** Candidate sees a newer tool catalog. The shadow is now measuring two differences at once — the model and the catalog. Promote context to the manifest; refuse the pair if versions diverge.
- **Long-retained raw text.** Shadow logs with raw text at 365-day TTL is a privacy bomb. Hash at rest; short TTL.
- **Shadow as a load test.** Pointing the shadow at a candidate that cannot sustain the production QPS turns the shadow into a performance regression — and a drop rate that hides a real quality gap.
- **Judge version churn.** Re-scoring last week's shadow with a new judge version and comparing to the prior week's result. Pin the judge version on the manifest; a new judge is a new analysis run.
- **One scalar win rate.** A win rate without CI, slice table, or cost ledger is a vibe. Report all three.
- **Production weights derived in the report script.** A reviewer cannot recompute the aggregate. Commit weights in a YAML with its derivation window.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function asks for repeatability and documented tools; the committed event log, manifest, and clustered-bootstrap seed are the direct operationalization. `MANAGE` asks that pre-deployment risk decisions be recorded; the shadow is itself the pre-deployment record.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML04 Membership Inference Attack** and **ML05 Model Theft** motivate the ACL + redaction + short-retention defaults on the shadow log and the ban on externally queryable candidate endpoints. **ML09 Output Integrity Attacks** motivates the parity rule — if the candidate has access to context the incumbent lacks, the shadow is measuring the context, not the model.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0040 ML Model Inference API Access` describes the candidate endpoint as an attack surface (treat the shadow plane as privileged); `AML.T0043 Craft Adversarial Data` motivates the judge-version pinning and the ban on re-scoring across judge versions.

<!-- Local exercise context: the fork-at-router architecture, the specific slice tags (`lang:en`, `intent:billing`, `tenure:new_user`), the `tools-v7` catalog version, and the 30-day retention are illustrative defaults for a chat product with a stable router layer. Replace them with your product's fork architecture, slice taxonomy, and privacy posture before adopting. The offline regression gates that must pass before a candidate becomes eligible for a shadow are the subject of [exercise-01](../exercise-01-offline-regression-suite-with-gates/SOLUTION.md); the A/B experiment that fires after the shadow finds no slice regressions is [exercise-03](../exercise-03-ab-test-with-cuped/SOLUTION.md); the continuous-monitoring version of this comparison is [exercise-04](../exercise-04-sequential-testing-for-continuous-monitoring/SOLUTION.md); the observability stack that surfaces shadow drops as alerts is [exercise-05](../exercise-05-production-eval-observability-integration/SOLUTION.md). -->
