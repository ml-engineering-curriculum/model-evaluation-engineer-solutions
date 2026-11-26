# exercise-05 — Eval in CI with SLOs — Solution

## 1. Solution overview

An eval that runs in a notebook on the model engineer's laptop is an eval that blocks exactly zero bad merges. Eval in CI is the control that catches a regression **before it rides the main branch to a deploy**. The contract is that every pull request to a model, prompt, or metric repo triggers a scoped eval run whose pass/fail is a merge gate; the gate is tied to a committed SLO, uses pinned artifacts from the registry, and completes inside a budget that keeps PR iteration speeds workable. If the CI eval is a 90-minute job that costs $300, engineers route around it. If it is a 6-minute smoke on a pinned slice set with a nightly deep eval behind it, it becomes the default path.

The design hinges on four non-negotiables:

- **Two eval tiers: PR smoke and nightly deep.** The PR eval runs on a committed `smoke` slice (small, high-power, representative); it is capped at ~10 minutes and ~$5 per run. The nightly deep eval runs on the full regression set with judges; it is the ground truth for the weekly SLO burn. The PR smoke's job is to catch 95% of regressions fast; the nightly's job is to catch the rest.
- **SLO-mapped gates, not invented thresholds.** Every PR-eval gate is the offline proxy for a declared SLO (see [mod-110 exercise-01](../../mod-110-production-eval-regression/exercise-01-offline-regression-suite-with-gates/SOLUTION.md)). "accuracy must be ≥ 0.80" is a vibe; "exact_match on `smoke.lang:en` must not regress > 0.5pp vs. the main-branch baseline (SLO-QUALITY-01)" is a gate.
- **The GitHub status check is one check, with evidence links.** One red/green on the PR, with a link to the per-run `REPORT.md`, the warehouse row, and the baseline the run was compared against. Twenty orange checks for twenty metrics is how reviewers learn to ignore them.
- **Determinism and reproducibility are enforced in CI itself.** The pipeline recomputes the eval-set SHA, pins the baseline-run SHA, pins the artifact URIs via the registry, and reruns the scorer twice to verify byte-identical output. A flaky gate loses merge-gate credibility in two weeks.

The reference answer has five deliverables:

1. A **CI workflow** (`.github/workflows/eval-ci.yml`) — PR trigger, pinned artifact resolution, estimate-then-submit, poll-then-gate, post-status-check.
2. A **gate configurator** (`ci/gates.yml`) — the per-metric, per-slice shipping deltas bound to SLO ids, overridable only via an audited `override` label on the PR.
3. A **status-check writer** (`ci/post_status.py`) — one GitHub check whose summary is the merge gate, with links to the full report and the warehouse row.
4. A **budget guard** (`ci/budget.py`) — pre-flight cost estimation that rejects a PR eval that would exceed the per-PR cap.
5. A **nightly workflow** (`.github/workflows/eval-nightly.yml`) — scheduled deep eval with judge passes, SLO burn-rate alerts, and a weekly digest of worst-regressed slices across PRs.

This maps directly to the NIST AI RMF `MEASURE` and `MANAGE` functions: `MEASURE` asks that evaluations be "continuous in the operational context" — a per-PR eval gate operationalizes continuity for model development the same way a per-request judge operationalizes continuity for serving. `MANAGE` asks for documented alert-to-owner routes — one GitHub check with a named SLO and a named owner is the routing ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML06 AI Supply Chain Attacks** (a PR that quietly swaps a dataset or judge version is a supply-chain change; the pinned-URI gate catches it before merge) and **ML09 Output Integrity Attacks** (a PR eval that reports pass on a half-completed run masks a regression; the completeness check plus SHA verification is the control) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0020 Poison Training Data` and `AML.T0018 Backdoor ML Model` are both failure modes the PR eval can surface pre-merge, assuming the gate's `smoke` slice taxonomy covers the sensitive population ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Directory layout

```
.
├── .github/workflows/
│   ├── eval-ci.yml              # PR smoke
│   └── eval-nightly.yml         # nightly deep
├── ci/
│   ├── gates.yml                # per-metric, per-slice shipping deltas
│   ├── smoke_spec.yml           # the RunSpec template for PR smoke
│   ├── nightly_spec.yml         # the RunSpec template for nightly
│   ├── estimate.py              # calls the cost estimator
│   ├── submit.py                # calls the orchestrator
│   ├── wait.py                  # polls run status with a timeout
│   ├── gate.py                  # reads report.json, applies gates.yml
│   ├── post_status.py           # writes one GitHub status check
│   └── budget.py                # local budget guard (per-PR cap)
└── eval_sets/
    └── smoke/
        ├── items.jsonl
        └── items.sha256
```

### 2.2 PR workflow

```yaml
# .github/workflows/eval-ci.yml
name: eval-ci
on:
  pull_request:
    branches: [main]
    paths:
      - "models/**"
      - "prompts/**"
      - "metrics/**"
      - "judges/**"
      - "eval_sets/smoke/**"
      - "ci/**"
      - ".github/workflows/eval-ci.yml"

concurrency:
  group: eval-ci-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  smoke:
    name: eval smoke
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      pull-requests: write
      statuses: write
    env:
      EVAL_PLATFORM_TOKEN: ${{ secrets.EVAL_PLATFORM_TOKEN }}
      REGISTRY_URL: ${{ vars.REGISTRY_URL }}
      ORCHESTRATOR_URL: ${{ vars.ORCHESTRATOR_URL }}
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip
      - run: pip install -r ci/requirements.txt

      # --- Pin inputs: fail fast if any artifact URI is bare -----------
      - name: Resolve pinned artifacts
        run: python -m ci.resolve_spec ci/smoke_spec.yml > /tmp/spec_resolved.json

      # --- Verify the smoke eval set has not drifted -------------------
      - name: Verify eval-set SHA
        run: python -m ci.verify_sha eval_sets/smoke

      # --- Pre-flight estimate; reject over per-PR cap -----------------
      - name: Estimate cost
        id: est
        run: python -m ci.estimate /tmp/spec_resolved.json > /tmp/estimate.json

      - name: Budget guard
        run: python -m ci.budget /tmp/estimate.json --max-dollars 5.00

      # --- Submit the run; wait with a hard timeout --------------------
      - name: Submit eval run
        id: submit
        run: python -m ci.submit /tmp/spec_resolved.json > /tmp/run_id.txt

      - name: Wait for completion
        run: python -m ci.wait "$(cat /tmp/run_id.txt)" --timeout-minutes 12

      # --- Gate against committed deltas; writes decision.json ---------
      - name: Gate
        id: gate
        run: python -m ci.gate --run "$(cat /tmp/run_id.txt)" --gates ci/gates.yml --out /tmp/decision.json

      # --- Determinism check: rerun the scorer and diff ----------------
      - name: Determinism re-check
        run: python -m ci.rescore_and_diff "$(cat /tmp/run_id.txt)"

      # --- Post ONE status check with the report link ------------------
      - name: Post status
        if: always()
        run: >
          python -m ci.post_status
          --run "$(cat /tmp/run_id.txt)"
          --decision /tmp/decision.json
          --estimate /tmp/estimate.json

      # --- Fail the job if gate blocks and no override label -----------
      - name: Enforce gate
        run: python -m ci.enforce_gate /tmp/decision.json --pr ${{ github.event.pull_request.number }}
```

Rules the workflow enforces:

- **Trigger paths are explicit.** A PR that only touches docs does not run the eval. A PR that touches `prompts/` does; prompt changes shift judge verdicts.
- **`concurrency.cancel-in-progress` is set per-PR.** A new push cancels the stale run; the platform is not spending on a run whose output is already stale.
- **Pre-flight estimate is a hard step.** An unestimated run is rejected before submit; a run above the per-PR cap fails the workflow with a clear message, not silently.
- **Determinism is enforced in CI.** The scorer runs twice; a non-identical output fails the workflow. Flaky gates are caught at the source, not after a week of merges.
- **One status check is written in `always()`.** A workflow failure still posts a check; a transient CI infra blip does not look like a gate pass.

### 2.3 Gate config

```yaml
# ci/gates.yml
schema_version: 1
baseline_strategy: main_branch_last_green     # PR eval compares against the
                                              # last green eval run on main.
baseline_max_age_hours: 48                    # too-old baseline fails loud.
pr_eval_set: eval_sets/smoke                  # the smoke set, not the full set
gates:
  - metric: metrics/exact-match@v0.4.2
    slice: lang:en
    ship_delta: { kind: absolute, value: -0.005 }  # may drop ≤ 0.5pp
    disposition: block
    slo_ref: SLO-QUALITY-01
    owner: model-eval@team
  - metric: metrics/exact-match@v0.4.2
    slice: lang:es
    ship_delta: { kind: absolute, value: -0.010 }
    disposition: block
    slo_ref: SLO-QUALITY-01
    owner: model-eval@team
  - metric: metrics/semantic-f1@v0.4.2
    slice: intent:billing
    ship_delta: { kind: absolute, value: -0.020 }
    disposition: block
    slo_ref: SLO-QUALITY-02
    owner: model-eval@team
  - metric: metrics/refusal-rate@v0.4.2
    slice: lang:en
    ship_delta: { kind: absolute, value: +0.005 }
    disposition: warn
    slo_ref: SLO-UX-01
    owner: product@team
  - metric: metrics/p95-latency-ms@v0.4.2
    slice: all
    ship_delta: { kind: absolute, value: +10 }
    disposition: block
    slo_ref: SLO-PERF-01
    owner: inference-infra@team

override:
  label: "eval-override"                  # applying this label skips gate failure
  requires_review_from: ["@org/model-eval-approvers"]
  audit: committed to the warehouse as `override_used`
```

Rules the gate config enforces:

- **Every gate names a metric URI (pinned), a slice, a ship delta, a disposition, an SLO id, and an owner.** No anonymous gates. A reviewer who hits a red gate can see the owner on the PR check.
- **Baseline strategy is declared.** "last green main" is the common choice; alternatives (fixed golden run, rolling 7-day median) are allowed but must be committed in this file.
- **Baseline age is capped.** A 10-day-old baseline on a fast-moving codebase is a false green; the gate fails loud instead of silently comparing against drift.
- **Override is a labeled, reviewed, audited escape.** A merge that bypasses the eval gate is recorded; the warehouse row carries `override_used=true` and the reviewer id.

### 2.4 Status check writer

```python
"""Post one GitHub status check per PR eval run. Idempotent on (sha, context).

The check summary is the merge gate. The body is the evidence trail."""

from __future__ import annotations

import json
import sys


def main(run_id: str, decision_path: str, estimate_path: str, github) -> int:
    decision = json.loads(open(decision_path).read())
    est = json.loads(open(estimate_path).read())

    state = _state_from(decision)                   # success | failure | pending
    description = _one_line(decision, est)          # shows next to the check name
    details_url = _warehouse_url(run_id)

    github.repos.create_commit_status(
        sha=github.pr_head_sha,
        state=state,
        context="eval-ci/smoke",
        description=description[:140],
        target_url=details_url,
    )

    body = _render_pr_comment(decision, est, run_id)
    github.issues.upsert_comment(
        issue_number=github.pr_number,
        marker="<!-- eval-ci-report -->",
        body=body,
    )
    return 0


def _state_from(decision: dict) -> str:
    if decision["overall"] == "block":
        return "failure"
    if decision["overall"] == "ship_with_warnings":
        return "success"            # warnings are informational; they do not block merge
    return "success"


def _one_line(decision: dict, est: dict) -> str:
    n_fail = sum(1 for g in decision["gates"] if g["disposition"] == "block" and g["verdict"] == "fail")
    n_warn = sum(1 for g in decision["gates"] if g["disposition"] == "warn" and g["verdict"] == "fail")
    cost = est["high_dollars"]
    if n_fail:
        return f"{n_fail} blocking, {n_warn} warnings · ${cost:.2f}"
    if n_warn:
        return f"pass with {n_warn} warnings · ${cost:.2f}"
    return f"pass · ${cost:.2f}"


def _render_pr_comment(decision, est, run_id) -> str:
    rows = []
    for g in decision["gates"]:
        if g["disposition"] == "block" and g["verdict"] == "fail":
            rows.append(
                f"| ❌ | `{g['metric']}` | `{g['slice']}` | "
                f"{g['delta']:+.4f} vs. {g['ship_delta']:+.4f} | "
                f"**{g['slo_ref']}** · {g['owner']} |"
            )
    for g in decision["gates"]:
        if g["disposition"] == "warn" and g["verdict"] == "fail":
            rows.append(
                f"| ⚠️ | `{g['metric']}` | `{g['slice']}` | "
                f"{g['delta']:+.4f} vs. {g['ship_delta']:+.4f} | "
                f"**{g['slo_ref']}** · {g['owner']} |"
            )
    lines = [
        "## eval-ci / smoke",
        "",
        f"**Decision:** `{decision['overall']}` · **Run:** [`{run_id}`]({_warehouse_url(run_id)}) · "
        f"**Cost:** ${est['high_dollars']:.2f} (est.)",
        "",
        "| | metric | slice | delta vs. ship | SLO · owner |",
        "|---|---|---|---|---|",
        *rows if rows else ["| ✅ | — | — | all deltas within tolerance | — |"],
        "",
        "<sub>Baseline: last green eval on `main`. Full report: "
        f"[`REPORT.md`]({_warehouse_url(run_id) + '/REPORT.md'})</sub>",
    ]
    return "\n".join(lines)


def _warehouse_url(run_id: str) -> str:
    return f"https://eval.internal/runs/{run_id}"
```

Rules the writer enforces:

- **One status context.** `eval-ci/smoke` is the single merge-blocking check; there are no sibling checks for "accuracy", "f1", "latency." Reviewers see one red or one green.
- **The body is a table of failures with the SLO and owner on the first screen.** A reviewer reads the PR comment once; the first line of the body is the triage information.
- **Warnings are not failures.** The check is green with a warning summary; the body lists the warnings. A warn gate that blocked merges would train reviewers to ignore it.
- **Upsert the comment, do not append.** A re-run of the workflow replaces the comment in place. A PR comment history with ten stale "eval-ci / smoke" comments is noise.

### 2.5 Budget guard

```python
"""Local budget guard for the PR eval. Reads the estimate JSON and rejects
if the high-bound exceeds the committed per-PR cap.

The platform-level budget check (see mod-111 exercise-03) is the authoritative
one; this is the PR-local pre-check that fails fast with an actionable error."""

from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("estimate_path")
    ap.add_argument("--max-dollars", type=float, required=True)
    args = ap.parse_args()

    est = json.loads(open(args.estimate_path).read())
    hi = float(est["high_dollars"])
    if hi > args.max_dollars:
        sys.stderr.write(
            f"estimated cost ${hi:.2f} > per-PR cap ${args.max_dollars:.2f}\n"
            "Likely causes:\n"
            "  - smoke eval set grew beyond the committed size\n"
            "  - a new judge was added to smoke_spec.yml; use nightly_spec.yml instead\n"
            "  - model decoding budget (max_tokens) was raised; revert or justify in PR\n"
        )
        return 2
    print(f"budget ok: ${hi:.2f} <= ${args.max_dollars:.2f}")
    return 0
```

Rules:

- **Fail fast, not after the run.** A $200 PR run that fails budget at the orchestrator has already queued; the PR-local guard catches it in seconds.
- **The error message names the common causes.** An engineer whose PR fails the guard sees the three likely edits in the error stream; they do not need to open docs.

### 2.6 Nightly workflow

```yaml
# .github/workflows/eval-nightly.yml
name: eval-nightly
on:
  schedule:
    - cron: "0 7 * * *"      # 07:00 UTC daily
  workflow_dispatch: {}

jobs:
  deep:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    env:
      EVAL_PLATFORM_TOKEN: ${{ secrets.EVAL_PLATFORM_TOKEN }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11", cache: pip }
      - run: pip install -r ci/requirements.txt

      - name: Resolve pinned artifacts (nightly)
        run: python -m ci.resolve_spec ci/nightly_spec.yml > /tmp/spec_resolved.json

      - name: Estimate + submit
        run: |
          python -m ci.estimate /tmp/spec_resolved.json > /tmp/estimate.json
          python -m ci.budget /tmp/estimate.json --max-dollars 150.00
          python -m ci.submit /tmp/spec_resolved.json > /tmp/run_id.txt

      - name: Wait (long)
        run: python -m ci.wait "$(cat /tmp/run_id.txt)" --timeout-minutes 110

      - name: Promote baseline if green
        run: python -m ci.promote_baseline "$(cat /tmp/run_id.txt)"

      - name: SLO burn-rate alerts
        run: python -m ci.slo_burn_alerts --window 7d

      - name: Weekly digest (Monday only)
        if: ${{ github.event.schedule == '0 7 * * 1' || github.event_name == 'workflow_dispatch' }}
        run: python -m ci.weekly_digest --out /tmp/digest.md
      - name: Post weekly digest
        if: ${{ github.event.schedule == '0 7 * * 1' }}
        run: python -m ci.slack_post --file /tmp/digest.md --channel eval-ops
```

Rules the nightly enforces:

- **A nightly green run promotes the baseline.** The PR gate compares against this; the baseline is never older than ~24h.
- **The nightly also fires the SLO burn-rate alerts** — a slow regression that drifts a slice by 0.2pp per day is invisible to a single PR check but visible to a 7-day burn.
- **The weekly digest is a one-shot Slack post.** On Mondays, the slowest-regressed slices and the top PR-override list land in the eval-ops channel; the digest is the surface that keeps the gate's credibility honest.

### 2.7 Enforce step

```python
"""Final step in the PR workflow. Reads decision.json; if the overall is
`block` and the `eval-override` label is not present on the PR, exits non-zero.

An override is audited: the warehouse row for the run is updated with
`override_used=true, override_approver=<label-setter>` BEFORE the exit 0."""

from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("decision_path")
    ap.add_argument("--pr", type=int, required=True)
    args = ap.parse_args()

    decision = json.loads(open(args.decision_path).read())
    if decision["overall"] != "block":
        return 0

    pr = _github.get_pr(args.pr)
    labels = {label.name for label in pr.labels}
    if "eval-override" not in labels:
        sys.stderr.write(
            f"eval-ci gate blocks merge: {decision['overall']}. "
            "Apply the `eval-override` label (requires model-eval-approvers review) "
            "if this regression is intentional.\n"
        )
        return 1

    approver = _github.first_label_event(args.pr, "eval-override").actor.login
    if not _is_in_group(approver, "model-eval-approvers"):
        sys.stderr.write(
            f"override label applied by {approver} but they are not in "
            "@org/model-eval-approvers. Have an approver re-apply the label.\n"
        )
        return 1

    _warehouse.record_override(
        run_id=decision["run_id"],
        pr_number=args.pr,
        approver=approver,
    )
    return 0
```

Rules the enforcer enforces:

- **Override is a label applied by an approver, not a config field.** A config field would require a PR edit; a label is a reviewable social surface.
- **The warehouse records the override.** The weekly digest surfaces "N overrides this week, broken down by slice"; a rising override rate is a signal that the gate is miscalibrated (either too strict, or genuinely catching regressions that are then waved through).

## 3. Validation steps

1. **Path trigger coverage.** A PR touching only docs does not spawn the eval workflow (cost control); a PR touching `prompts/` does.
2. **Bare-URI rejection.** A `smoke_spec.yml` with `datasets/billing-chats` (no `@...`) fails `resolve_spec.py` with a clear error; the workflow does not submit.
3. **Eval-set SHA drift.** A manual edit to `eval_sets/smoke/items.jsonl` without a new `items.sha256` fails the `Verify eval-set SHA` step.
4. **Pre-flight budget rejection.** A `smoke_spec.yml` whose high-bound estimate exceeds the $5 per-PR cap fails the `Budget guard` step with a diagnostic naming common causes.
5. **Submit idempotency.** A re-run of the same workflow (same PR SHA) reuses the same `run_id` via idempotency key; no parallel run.
6. **Gate determinism.** `rescore_and_diff` reruns the scorer and asserts the second `report.json` matches the first byte-for-byte; a mismatch fails CI.
7. **Status check content.** On a synthetic failing gate, the GitHub check description names the count of blocking gates, warnings, and the dollar figure; the PR comment body first row lists the failing metric, slice, delta, SLO, owner.
8. **Override flow.** A PR with a blocking gate and no `eval-override` label fails `enforce_gate`; apply the label as a non-approver, re-run, still fails; apply as an approver, re-run, `enforce_gate` passes and the warehouse records the override.
9. **Baseline freshness.** A synthetic `main`-branch last-green-eval older than `baseline_max_age_hours` makes the gate fail loudly with "baseline too old" rather than silently passing on drift.
10. **Nightly promote-baseline.** A green nightly run with `environment='prod'` writes its run id to `baselines.last_green_main`; a red nightly does not.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the pipeline being **a single merge gate tied to SLOs with evidence**, not a scoreboard.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | PR workflow triggers only on model/prompt/metric/eval-config paths | 1 | `.github/workflows/eval-ci.yml` has an explicit `paths` filter; a docs-only PR does not fire. |
| R2 | Every eval artifact URI is pinned in the spec; bare URIs rejected | 1 | `resolve_spec.py` fails on bare names; test covers. |
| R3 | Pre-flight cost estimate; per-PR cap enforced locally in CI | 1 | `estimate.py` + `budget.py`; exceeding cap fails fast with a diagnostic. |
| R4 | One GitHub status check per PR, with a one-line summary and a link to the full report | 2 | `post_status.py`; a synthetic PR shows one check and one upserted comment. |
| R5 | Gates are per (metric, slice) with ship delta, disposition, SLO id, owner | 1 | `gates.yml` has all five fields per gate. |
| R6 | Baseline is the last green nightly on main; age cap enforced | 1 | `baseline_max_age_hours` is checked; stale baseline fails loud. |
| R7 | Determinism re-check in CI (rescore and diff) | 1 | Scorer reruns; byte-identical required. |
| R8 | Override is a labeled, approver-restricted, audited bypass | 1 | `eval-override` label; only approvers' label-applications satisfy; warehouse records the row. |
| R9 | Nightly workflow runs deep eval, promotes baseline, fires SLO burn alerts, and posts a weekly digest | 1 | `eval-nightly.yml` covers all four; digest posts to a committed channel. |

**Passing bar:** 7 / 10. R4 is non-negotiable — twenty orange status checks train reviewers to ignore all of them; one gate with evidence is the control. R7 is the second non-negotiable: a flaky gate loses credibility within weeks.

Reviewer checklist:

- [ ] The PR workflow fires only on relevant paths.
- [ ] Every URI in `smoke_spec.yml` is pinned (@sha256 or @vX.Y.Z or an audited alias).
- [ ] The budget guard fails a `smoke_spec.yml` that exceeds the per-PR cap.
- [ ] Exactly one GitHub status check is posted per PR; body comment is upserted.
- [ ] Each gate names metric, slice, delta, disposition, SLO id, owner.
- [ ] Baseline freshness is enforced; stale baselines fail the gate.
- [ ] Scorer determinism is re-checked in CI.
- [ ] Override label is restricted to approvers; the warehouse records the override.
- [ ] Nightly promotes the baseline on green and fires SLO burn alerts.
- [ ] Weekly digest surfaces the top-regressed slices and the override rate.

## 5. Common mistakes

- **Running the full nightly eval on every PR.** A 90-minute, $150 PR check is an eval nobody runs. Smoke slice for PR; full set at night.
- **Twenty status checks, one per metric.** Reviewers learn to merge through the orange. One check, one link.
- **No baseline freshness check.** A 10-day-old baseline on a fast-moving codebase silently drifts; the gate passes everything. Cap the age.
- **Baseline chosen by the PR author.** "I compared against last Tuesday because the last green was anomalous" is how a regression rides into main. Baseline is the `main`-branch last green; period.
- **Bare URIs in the spec.** `datasets/billing-chats` resolves to `latest` and the gate compares against whatever's current; a dataset publish changes PR results without a commit. Pin everything.
- **No pre-flight estimate.** A PR that uses a new $4-per-call judge doubles the per-PR cost silently. Estimate first.
- **Override as a config edit.** Editing `gates.yml` to lower a threshold to merge a specific PR silently loosens the gate for every future PR. Use a labeled override; the thresholds are not touched.
- **No audit on override.** An override that is not recorded becomes untracked debt; the weekly override rate becomes unreadable. Record every override with approver and reason.
- **Determinism unchecked.** A bootstrap with a run-time seed makes the scorer non-deterministic; two reruns disagree on pass/fail by chance. Pin seeds; rerun in CI; diff.
- **Workflow file permissions default to read-only.** `pull-requests: write` and `statuses: write` are required to post the check and the comment; omitting them silently drops the status.
- **No `concurrency` group.** Rapid pushes accumulate workflow runs; the platform bills for runs whose output is already stale. Set the group and `cancel-in-progress: true`.
- **Override approver list in a wiki.** The CI enforcer checks a GitHub team; the wiki says something else; a drift is a security surprise. Resolve approver group from the source the enforcer reads.
- **Nightly silently fails and nobody notices.** A nightly that red-greens is no longer a baseline; the PR gate starts comparing against a stale run and passes everything. Fail the nightly loudly (page); add a "last-green-age" metric to the dashboard.
- **PR smoke eval set grown to full size.** A smoke set that doubles in size over six months is a smoke set that costs $20 and takes 20 minutes. Commit the size floor and fail CI on growth above a committed ceiling.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function asks for evaluations that are continuous, repeatable, and tied to the operational context; a per-PR eval gate operationalizes continuity for the model-development loop, and the SLO reference on every gate ties the measurement to the operational context. The `MANAGE` function asks for documented alert-to-owner routes; one GitHub check with a named SLO and a named owner is the route for a merging engineer.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML06 AI Supply Chain Attacks** describes the risk of silent swaps of datasets, judges, or metrics; the pinned-URI resolve step is the pre-merge control. **ML09 Output Integrity Attacks** motivates the completeness check and the determinism re-check — a partially-completed or non-deterministic run that reports pass is the single worst failure mode for a merge gate.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0020 Poison Training Data` and `AML.T0018 Backdoor ML Model` are both failure modes the PR gate can surface pre-merge. The gate's `smoke` slice taxonomy must cover the sensitive population for this to hold — a smoke eval set that omits the targeted slice is a smoke eval set that misses the attack.

<!-- Local exercise context: The specific per-PR cap ($5), the 12-minute PR timeout, the $150 nightly cap, the 48-hour baseline age cap, the `eval-override` label name, and the Monday-07:00-UTC digest cadence are illustrative defaults for a chat-product eval platform with a medium PR velocity. Replace them with your team's PR iteration-speed target, your nightly deep-eval dollar budget, and your approver-group names before adopting. Sibling exercises: the registry whose URIs every spec pins is [exercise-01](../exercise-01-versioned-registry-design/SOLUTION.md); the orchestrator whose `submit`/`wait`/`fetch` endpoints the workflow calls is [exercise-02](../exercise-02-multi-runner-orchestration/SOLUTION.md); the cost controller whose per-PR cap is the authoritative ceiling behind the local budget guard is [exercise-03](../exercise-03-platform-cost-controls/SOLUTION.md); the warehouse whose `fact_run_aggregates` rows back the PR comment's details link, the override audit, and the weekly digest is [exercise-04](../exercise-04-eval-data-warehouse-and-lineage/SOLUTION.md). -->
