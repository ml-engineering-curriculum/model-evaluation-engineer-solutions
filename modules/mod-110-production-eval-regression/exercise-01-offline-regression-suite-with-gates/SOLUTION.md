# exercise-01 — Offline Regression Suite With SLO-Mapped Gates — Solution

## 1. Solution overview

An offline regression suite is the last place a release can be blocked before it reaches live traffic. It has one job: on every candidate build, replay a frozen eval set, compute a committed list of metrics per slice, and emit a **ship / no-ship** decision whose evidence trail is good enough that a reviewer six months later can reconstruct why. If the suite's output is one scalar accuracy number, it will quietly ship a model that regressed on the 4% of traffic that generates 60% of revenue. If it is "pass" with no slice table, it will ship a model that regressed on a protected group.

The design has to tie the gates to a published SLO, not an invented threshold. An SLO says "p95 end-to-end latency ≤ 300 ms at 99.5% availability over 28 days" or "harmful-content rate ≤ 0.1% at 95% confidence." A gate is the offline proxy for one SLO: "if the candidate's p95 latency on `regression_v3` exceeds the baseline p95 + 10 ms, block." Without the SLO, a gate is a vibe.

The reference answer has five deliverables:

1. A **committed eval set** (`regression_v3.jsonl` + `regression_v3.sha256`) with a documented slice taxonomy, per-slice size floor, and a provenance line per item.
2. A **metrics config** (`metrics.yaml`) that pins each metric to one or more SLOs, names the direction of harm, and declares the aggregator (bootstrap mean + 95% CI, or quantile + CI).
3. A **gating policy** (`gates.yaml`) that, per metric and slice, names a baseline run, a ship delta, a `cohen_h` / minimum detectable effect, and a failure disposition (block, warn, record).
4. A **runner** that produces `report.json` with per-item predictions, per-slice aggregates, baseline deltas, and the go / no-go decision.
5. A **report template** (`REPORT.md`) that a human reads: the slices that changed, the SLOs they map to, the owner for each failed gate.

This maps directly to the NIST AI RMF `MEASURE` function, which asks that metrics be "tested, documented, and tied to an identified operational context" and that evaluations be "repeatable, with documented tools and assumptions" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10: **ML02 Data Poisoning Attack** is the risk of a drifted eval set (the baseline silently shifts and the gate always passes), and **ML09 Output Integrity Attacks** motivates recording per-item predictions on disk, not just slice aggregates — a candidate that regressed on exactly the items a legacy heuristic used to catch is invisible from aggregates alone ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS frames the eval itself as a defended asset: `AML.T0018 Backdoor ML Model` and `AML.T0020 Poison Training Data` both describe failure modes that an offline regression suite with pinned ground truth can surface before the model is promoted ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Directory layout

```
regression_suite/
  README.md
  eval_sets/
    regression_v3/
      items.jsonl                 # one eval item per line
      items.sha256
      slices.yaml                 # slice taxonomy + per-slice floor
      PROVENANCE.md               # how each slice was built; who signed off
  config/
    metrics.yaml                  # metric → SLO mapping
    gates.yaml                    # per-metric, per-slice gates
  runner/
    __init__.py
    predict.py                    # candidate(build) → predictions.jsonl
    score.py                      # predictions + eval_set → report.json
    gate.py                       # report.json + gates.yaml → decision.json
  baselines/
    baseline_2026-10-01/
      report.json                 # last promoted build's report
      run.yaml                    # manifest (build sha, data sha, model id)
  runs/
    cand_2026-11-20/
      predictions.jsonl
      report.json
      decision.json
      REPORT.md
      run.yaml
  tests/
    test_slice_floor.py           # every slice meets size floor
    test_gate_logic.py            # ship delta semantics
    test_baseline_pin.py          # baseline is referenced, not inferred
```

Rule: **predictions, aggregates, and the decision are all committed on disk** before the gate fires. A pass decision whose evidence is stdout is not evidence.

### 2.2 Eval set and slice taxonomy

An eval set is a frozen, committed artifact with a SHA. The slice taxonomy is the second committed artifact; changing either bumps the eval-set version (`regression_v3` → `regression_v4`), not a silent in-place edit. One eval item looks like:

```json
{
  "item_id": "it-00042",
  "input": { /* model-specific; captured verbatim */ },
  "ground_truth": { /* ... */ },
  "slice_tags": ["lang:en", "intent:billing", "tenure:new_user"],
  "provenance": "sampled from 2026-09 billing logs; redacted by pipeline v2.4",
  "created_at": "2026-09-14"
}
```

`slices.yaml` pins the taxonomy and the per-slice **size floor**. A slice below its floor is a gate on sand — the CI reports a `MIN_SAMPLE` warning and the gate for that slice is a `record` disposition, not a `block`.

```yaml
# eval_sets/regression_v3/slices.yaml
schema_version: 1
slices:
  - name: lang_en
    tag: "lang:en"
    size_floor: 500
    rationale: >
      English traffic is the majority of production; a gate here with <500
      items has a CI wide enough to miss a 2pp regression.
  - name: lang_es
    tag: "lang:es"
    size_floor: 300
    rationale: >
      Spanish is 12% of production; below 300 items the gate is advisory.
  - name: intent_billing
    tag: "intent:billing"
    size_floor: 200
    rationale: >
      Billing errors are revenue-impacting; 200 items gives power to detect
      a 5pp regression at alpha=0.05.
  - name: new_user_first_7d
    tag: "tenure:new_user"
    size_floor: 400
    rationale: >
      New-user activation is the canonical NSM-adjacent cohort; this slice
      guards the SLO "new-user 7-day retention ≥ baseline - 1pp".
```

Four rules the slices.yaml file enforces:

- **Every slice has a size floor and a rationale.** A slice with "size_floor: 1" is not a slice; it is a trap for a reviewer who thinks the gate ran.
- **Tags are closed-set.** A new tag requires an update to `slices.yaml` and bumps the eval-set version.
- **Intersections are explicit.** `lang:en ∧ intent:billing` is its own named slice if it is gated; silently intersecting at report time hides regressions and inflates the number of gates.
- **Provenance is per-item.** A slice whose items cannot be re-derived from a committed pipeline is not reproducible.

### 2.3 Metrics config — SLO mapping

Every metric is declared with its direction, its aggregator, and the SLO it is the offline proxy for.

```yaml
# config/metrics.yaml
schema_version: 1
metrics:
  - name: exact_match
    direction: higher_is_better
    aggregator: { kind: bootstrap_mean, iters: 1000, seed: 20261120 }
    slo:
      id: SLO-QUALITY-01
      statement: "Exact-match accuracy on regression_v3 ≥ baseline - 1pp"
      owner: model-eval@team
  - name: semantic_f1
    direction: higher_is_better
    aggregator: { kind: bootstrap_mean, iters: 1000, seed: 20261120 }
    slo:
      id: SLO-QUALITY-02
      statement: "Semantic F1 ≥ baseline - 2pp per slice"
      owner: model-eval@team
  - name: refusal_rate
    direction: lower_is_better
    aggregator: { kind: wilson_proportion, alpha: 0.05 }
    slo:
      id: SLO-UX-01
      statement: "Refusal rate on answerable items ≤ 2%"
      owner: product@team
  - name: p95_latency_ms
    direction: lower_is_better
    aggregator: { kind: quantile, q: 0.95, bootstrap_iters: 1000 }
    slo:
      id: SLO-PERF-01
      statement: "Offline p95 latency ≤ 300 ms on the standard shape mix"
      owner: inference-infra@team
```

Why the aggregators are declared, not implied:

- A **bootstrap mean + CI** is appropriate for a 0/1 metric that is not a rate; the CI width is the signal that the slice is under-powered.
- **Wilson** is appropriate for a proportion; the normal-approximation CI breaks at the extreme rates (<5% or >95%) where refusal and safety metrics live.
- A **quantile with bootstrap CI** is the only honest way to report a p95; a point-estimate p95 moves by tens of ms with a handful of items.

Choice of aggregator is a decision that outlives any single run — committing it in `metrics.yaml` means two reruns of the suite produce byte-identical aggregates.

### 2.4 Gate policy

A gate is declared per (metric, slice). The policy names:

- a **baseline** (the last promoted build's `report.json`, pinned by run id),
- a **ship delta** (the tolerance; in absolute points or as a ratio),
- a **minimum detectable effect** derived from the slice size (so a passing gate on an under-powered slice reports a `LOW_POWER` warning, not a green tick),
- a **disposition** (`block`, `warn`, `record`).

```yaml
# config/gates.yaml
schema_version: 1
baseline_run: baselines/baseline_2026-10-01/report.json
default_alpha: 0.05
gates:
  - metric: exact_match
    slice: lang_en
    ship_delta: { kind: absolute, value: -0.005 }     # may drop ≤ 0.5pp
    disposition: block
    slo_ref: SLO-QUALITY-01
  - metric: exact_match
    slice: lang_es
    ship_delta: { kind: absolute, value: -0.01 }
    disposition: block
    slo_ref: SLO-QUALITY-01
  - metric: semantic_f1
    slice: intent_billing
    ship_delta: { kind: absolute, value: -0.02 }
    disposition: block
    slo_ref: SLO-QUALITY-02
  - metric: refusal_rate
    slice: lang_en
    ship_delta: { kind: absolute, value: 0.005 }      # refusal can rise ≤ 0.5pp
    disposition: warn
    slo_ref: SLO-UX-01
  - metric: p95_latency_ms
    slice: all
    ship_delta: { kind: absolute, value: 10 }         # p95 may regress ≤ 10 ms
    disposition: block
    slo_ref: SLO-PERF-01
```

Two rules the policy enforces:

- **The baseline is a run id, not a hardcoded number.** A "baseline accuracy = 0.84" in `gates.yaml` decays the moment the eval set changes. Referencing a baseline *report* means the comparison is always against a run that used the same eval set and metrics.
- **The ship delta is a one-sided tolerance.** It is always "the candidate may be this much worse than the baseline on this metric and slice." Unlimited improvement is fine; a two-sided test on the direction-of-harm metric would be a bug.

### 2.5 Runner: scoring and gating

`runner/score.py` consumes `predictions.jsonl` and the eval set and writes `report.json`:

```python
"""Score one candidate's predictions against the frozen eval set.

The output is one report.json with three sections: `per_item`, `per_slice`,
and `aggregates`. Nothing in the gate step reads outside this file."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
import numpy as np


@dataclass(frozen=True)
class MetricSpec:
    name: str
    direction: str
    aggregator: dict


def _bootstrap_mean(values: np.ndarray, iters: int, seed: int) -> dict:
    rng = np.random.default_rng(seed)
    n = len(values)
    if n == 0:
        return {"point": None, "ci_lo": None, "ci_hi": None, "n": 0}
    idx = rng.integers(0, n, size=(iters, n))
    resample_means = values[idx].mean(axis=1)
    return {
        "point": float(values.mean()),
        "ci_lo": float(np.quantile(resample_means, 0.025)),
        "ci_hi": float(np.quantile(resample_means, 0.975)),
        "n": int(n),
    }


def _wilson(k: int, n: int, alpha: float) -> dict:
    if n == 0:
        return {"point": None, "ci_lo": None, "ci_hi": None, "n": 0}
    from scipy.stats import norm
    z = norm.ppf(1 - alpha / 2)
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    halfw = z * np.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return {
        "point": float(p),
        "ci_lo": float(center - halfw),
        "ci_hi": float(center + halfw),
        "n": int(n),
    }


def _quantile_with_ci(values: np.ndarray, q: float, iters: int, seed: int) -> dict:
    rng = np.random.default_rng(seed)
    n = len(values)
    if n == 0:
        return {"point": None, "ci_lo": None, "ci_hi": None, "n": 0}
    idx = rng.integers(0, n, size=(iters, n))
    quantiles = np.quantile(values[idx], q, axis=1)
    return {
        "point": float(np.quantile(values, q)),
        "ci_lo": float(np.quantile(quantiles, 0.025)),
        "ci_hi": float(np.quantile(quantiles, 0.975)),
        "n": int(n),
    }


def aggregate(values: np.ndarray, spec: MetricSpec, alpha: float = 0.05) -> dict:
    kind = spec.aggregator["kind"]
    if kind == "bootstrap_mean":
        return _bootstrap_mean(values, spec.aggregator["iters"], spec.aggregator["seed"])
    if kind == "wilson_proportion":
        return _wilson(int(values.sum()), len(values), spec.aggregator.get("alpha", alpha))
    if kind == "quantile":
        return _quantile_with_ci(
            values, spec.aggregator["q"], spec.aggregator["bootstrap_iters"],
            spec.aggregator.get("seed", 0),
        )
    raise ValueError(f"unknown aggregator kind: {kind}")
```

`runner/gate.py` reads `report.json`, `baseline_report.json`, and `gates.yaml` and emits `decision.json`:

```python
"""Enforce gates. Deterministic, read-only against the two reports.

Output is one decision.json with per-gate verdicts; `overall` is `block`
iff any gate's disposition is `block` and its verdict is `fail`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class GateVerdict:
    metric: str
    slice: str
    disposition: str   # block | warn | record
    verdict: str       # pass | fail | low_power
    delta: float
    ship_delta: float
    cand_point: float
    base_point: float
    cand_ci: tuple[float, float]
    base_ci: tuple[float, float]
    slo_ref: str


def _sign(direction: str) -> int:
    return -1 if direction == "higher_is_better" else 1


def evaluate_gate(gate, metric_spec, cand_slice, base_slice, min_n) -> GateVerdict:
    cand = cand_slice["aggregates"][gate["metric"]]
    base = base_slice["aggregates"][gate["metric"]]
    delta = cand["point"] - base["point"]
    sign = _sign(metric_spec["direction"])
    # ship_delta is signed in the natural "worse" direction; e.g.
    # higher_is_better + ship_delta=-0.005 means candidate may be 0.5pp lower.
    ship = gate["ship_delta"]["value"]
    # "worse by at most ship" means sign*delta <= abs(ship)? Equivalent form:
    if metric_spec["direction"] == "higher_is_better":
        # fail iff delta < ship (ship is negative or zero)
        passed = delta >= ship
    else:
        # lower_is_better: fail iff delta > ship (ship is positive or zero)
        passed = delta <= ship
    verdict = "pass" if passed else "fail"
    if cand["n"] < min_n or base["n"] < min_n:
        verdict = "low_power"
    return GateVerdict(
        metric=gate["metric"],
        slice=gate["slice"],
        disposition=gate["disposition"],
        verdict=verdict,
        delta=delta,
        ship_delta=ship,
        cand_point=cand["point"],
        base_point=base["point"],
        cand_ci=(cand["ci_lo"], cand["ci_hi"]),
        base_ci=(base["ci_lo"], base["ci_hi"]),
        slo_ref=gate["slo_ref"],
    )


def overall_decision(verdicts: list[GateVerdict]) -> str:
    if any(v.disposition == "block" and v.verdict == "fail" for v in verdicts):
        return "block"
    if any(v.disposition == "warn" and v.verdict == "fail" for v in verdicts):
        return "ship_with_warnings"
    return "ship"
```

Design rules worth calling out:

- **Deterministic seeds.** The bootstrap seed is in `metrics.yaml`, not generated at run time. Two reruns of `score.py` on the same predictions produce identical CIs.
- **`low_power` is a third verdict, not a pass.** A slice below its size floor cannot earn a pass; the suite flags it and the reviewer decides whether to ship or wait.
- **Gates compare point-to-point, not CI-overlap.** CI overlap is a diagnostic, not a gate — two heavily overlapping CIs can still represent a shipping-relevant delta. Report the CIs; gate on the signed delta against the ship tolerance.
- **One disposition per gate.** A gate is either `block`, `warn`, or `record`. Mixed verdicts ("block in dev, warn in staging") are a debugging convenience, not a gate design; promote them to separate gate files per environment if needed.

### 2.6 `REPORT.md` — the human-facing summary

Every run writes a short `REPORT.md` that is the artifact a reviewer actually reads:

```markdown
# Candidate cand_2026-11-20 vs. baseline baseline_2026-10-01

**Overall decision:** block (1 blocking gate failed, 2 warnings)

## Blocking failures

| Metric | Slice | Baseline | Candidate | Delta | Ship delta | SLO |
|---|---|---|---|---|---|---|
| semantic_f1 | intent_billing | 0.812 [.799, .825] | 0.783 [.770, .796] | -0.029 | -0.02 | SLO-QUALITY-02 (product@team) |

## Warnings

| Metric | Slice | Delta | Ship delta | Notes |
|---|---|---|---|---|
| refusal_rate | lang_en | +0.009 | +0.005 | 0.4pp over tolerance |
| p95_latency_ms | all | +14 ms | +10 ms | tail inflated by new tokenizer path |

## Low-power slices

| Metric | Slice | n_candidate | n_baseline | Floor |
|---|---|---|---|---|
| exact_match | lang_pt | 142 | 148 | 300 |
```

The report lists **what regressed, which SLO it maps to, and who owns it** on the first page. A reviewer who cannot find the SLO owner in the first screen will route the ticket to whoever owns the model team by default, which is almost never the right person.

### 2.7 Run manifest

```yaml
# runs/cand_2026-11-20/run.yaml
run_id: cand_2026-11-20
eval_set:
  name: regression_v3
  sha256: <sha256 of eval_sets/regression_v3/items.jsonl>
candidate:
  build_sha: <git sha of the model repo>
  model_id: product-llm-v7-candidate
  decoding: { temperature: 0.0, max_tokens: 512 }
baseline_run: baselines/baseline_2026-10-01/report.json
metrics_config_sha: <sha256 of config/metrics.yaml>
gates_config_sha: <sha256 of config/gates.yaml>
runner_commit: <git sha>
seed: 20261120
cli: "python -m runner.predict --eval regression_v3 --out runs/cand_2026-11-20/ && python -m runner.score ... && python -m runner.gate ..."
```

The manifest is the row another engineer rereads six months later. A manifest missing the config SHAs is the common failure mode: someone edits `gates.yaml` to loosen a threshold, reruns, and the gate passes — with no evidence of the edit.

## 3. Validation steps

1. **Eval-set integrity.** CI recomputes `items.sha256` and compares to the committed value; a mismatch rejects the run. The eval set is not a mutable file.
2. **Slice-floor enforcement.** For every slice declared in `slices.yaml`, `len(items with that tag) ≥ size_floor`. A violation fails CI even if no gate uses that slice — a slice below its floor cannot earn a pass later.
3. **Determinism of score.** Running `python -m runner.score --in predictions.jsonl --out report.json` twice produces byte-identical `report.json` (seed in `metrics.yaml`; no clock, no env).
4. **Determinism of gate.** `gate.py` reads only `report.json`, `baseline_report.json`, and `gates.yaml`; `decision.json` is a function of these three files.
5. **Baseline-run existence.** `baseline_run` in `gates.yaml` resolves to a committed `report.json`; CI fails if the file is missing or if its `eval_set.sha256` differs from the candidate's.
6. **Config-SHA pinning.** The manifest's `metrics_config_sha` and `gates_config_sha` match the on-disk files; a mismatch means someone edited config after the run and the decision is not trustable.
7. **Direction semantics.** For every metric, a synthetic test produces a candidate that is one tick worse than baseline and asserts the gate fails; one tick better and asserts the gate passes.
8. **Low-power honesty.** A synthetic candidate with n below the slice floor produces `verdict=low_power` and does not count as a pass.
9. **Overall-decision rule.** `decision.overall == "block"` iff at least one gate with `disposition=block` has `verdict=fail`; otherwise `ship_with_warnings` if any `warn` gate failed; else `ship`.
10. **Report round-trip.** A reviewer can reconstruct the blocking-failures table in `REPORT.md` from `decision.json` and `report.json` alone; the Markdown is a rendering, not a separate source of truth.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the gate being **an audit trail with an owner**, not a single scalar.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Eval set is a committed artifact with a SHA and provenance | 1 | `items.sha256` matches; `PROVENANCE.md` names the pipeline and date for every slice. |
| R2 | Every slice has a committed size floor and a rationale | 1 | `slices.yaml` has `size_floor` and `rationale` for every slice; CI enforces the floor. |
| R3 | Every metric is pinned to an SLO id with a named owner | 2 | `metrics.yaml` declares `slo.id`, `slo.statement`, `slo.owner` for every metric. |
| R4 | Aggregators are declared (bootstrap / Wilson / quantile) with seeds | 1 | `metrics.yaml` names `kind` and `seed`; two reruns byte-identical. |
| R5 | Gates reference a baseline *run*, not a hardcoded number | 1 | `gates.yaml` names `baseline_run` as a path; CI fails if the file is missing. |
| R6 | Dispositions are declared (block / warn / record) and the overall decision rule is deterministic | 2 | `decision.json` reports `overall` and each gate verdict; synthetic tests pin the semantics. |
| R7 | `REPORT.md` surfaces failed gates with SLO and owner before anything else | 1 | First table of the report lists metric, slice, delta, SLO, owner. |
| R8 | Manifest pins eval set SHA, config SHAs, model id, baseline run, seed, CLI | 1 | `run.yaml` has every field; rerun of CLI reproduces per-item predictions. |

**Passing bar:** 7 / 10. R3 and R6 are non-negotiable — a gate with no SLO is a vibe; an overall decision whose rule is not deterministic is a vote.

Reviewer checklist:

- [ ] `items.sha256` matches the committed value.
- [ ] Every slice meets its `size_floor`; `low_power` slices are not counted as passes.
- [ ] Every metric in `metrics.yaml` names an SLO id, statement, and owner.
- [ ] `gates.yaml` references a baseline *run*; the file exists and uses the same eval set.
- [ ] `decision.json.overall` matches the rule: block ⇔ any blocking gate failed.
- [ ] `REPORT.md` first table names the blocking failures with metric, slice, delta, SLO, owner.
- [ ] Manifest's config SHAs match the on-disk `metrics.yaml` and `gates.yaml`.
- [ ] Rerun with the same seed produces byte-identical `report.json`.

## 5. Common mistakes

- **One scalar accuracy as the gate.** A single number averages the one slice that matters into the 90% of items where nothing changed. Slice the eval set and gate per slice.
- **Hardcoded baseline numbers in config.** `baseline_accuracy: 0.84` in `gates.yaml` goes stale the moment the eval set shifts; the gate silently always passes. Reference a baseline *run* file instead.
- **Slice floors invented at report time.** "This slice has 40 items, it is fine" is not a judgment; it is a bug. Floors are per-slice properties of the eval set, not reviewer-level.
- **CI from `scipy.stats.sem` on a 0/1 metric.** The normal-approximation CI misreports the extremes where refusal and safety metrics live. Use bootstrap or Wilson.
- **Two-sided test on a direction-of-harm metric.** Gating `|delta| ≤ tolerance` blocks a candidate that *improved*. The ship delta is one-sided.
- **CI overlap treated as a gate.** Two overlapping CIs can hide a shipping-relevant regression; a gate on CI overlap would pass nearly every candidate. Report the CIs; gate on the signed delta.
- **Non-deterministic bootstrap.** A bootstrap with `np.random` at module import uses a different seed each run; two reruns disagree on whether the same candidate passes. Pin the seed in `metrics.yaml`.
- **A `block` disposition on a low-power slice.** Blocking a release on a slice with 40 items is noise; the gate will flap. Make `low_power` a third verdict and let a reviewer decide, not the suite.
- **Dropping failing slices from the report.** "We removed `lang_pt` because it is noisy" is a decision that must be committed in `slices.yaml` — not a per-run edit in the report script.
- **Changing the eval set and the model in the same commit.** The regression is now unattributable: did quality drop, or did the eval set get harder? Version the eval set independently; a bump requires a new baseline run.
- **Manifest without config SHAs.** A reviewer six months later cannot tell whether `gates.yaml` was loosened to let the build through. Pin the SHAs.
- **"Flaky slice" as a disposition.** A slice whose aggregate moves run-to-run on the same build is a bug in the aggregator or a sample too small for the metric — not a license to ignore it.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function asks for metrics that are "tested, documented, and tied to an identified operational context"; mapping each metric in `metrics.yaml` to a named SLO with an owner is the direct operationalization. `MANAGE` asks that risk decisions be documented and owned; the per-slice size floor with a rationale and the committed gate dispositions are the ownership trail.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML02 Data Poisoning Attack** motivates pinning the eval set SHA — a shifting eval set silently moves the baseline and defeats the gate. **ML09 Output Integrity Attacks** motivates recording per-item predictions, not just slice aggregates — a candidate that silently regresses on exactly the items a legacy heuristic used to catch is invisible from a scalar.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0018 Backdoor ML Model` and `AML.T0020 Poison Training Data` describe failure modes a frozen-ground-truth regression suite can surface pre-promotion; the committed eval set and the pinned baseline are the controls.

<!-- Local exercise context: `regression_v3`, the SLO ids (`SLO-QUALITY-01`, `SLO-UX-01`, `SLO-PERF-01`), the specific slice tags (`lang:en`, `intent:billing`), the 500-item floor for `lang_en`, and the 300 ms p95 budget are illustrative defaults for a chat-product eval. Replace them with your product's slice taxonomy, SLO ids, and latency budget before adopting. Sibling exercises: the shadow-launch comparison that extends this suite to live traffic is [exercise-02](../exercise-02-shadow-launch-comparison/SOLUTION.md); the A/B experimental protocol that fires once a candidate passes the offline gates is [exercise-03](../exercise-03-ab-test-with-cuped/SOLUTION.md); the serving-latency benchmark that underlies `SLO-PERF-01` is [exercise-06](../exercise-06-mlperf-style-serving-benchmark/SOLUTION.md). -->
