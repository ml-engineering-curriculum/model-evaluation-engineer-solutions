# exercise-02 — SWE-bench Reproduction — Solution

## 1. Solution overview

SWE-bench is a reproducibility-hostile benchmark done well: each item is a real GitHub issue from a real Python repository at a frozen commit, scored by running a hidden test suite inside a per-task Docker image. The eval is useful precisely because it is end-to-end — the agent reads the issue, navigates the repo, edits files, and only "passes" when the hidden tests run green against its patch in an isolated container. The reproducibility hostility is the point: a benchmark that scores every candidate the same way has to control for the Python version, the pip graph, the OS packages, and the test-runner invocation, or it reports noise.

This exercise asks the learner to **reproduce** a SWE-bench run — not to beat it. The deliverable is a committed harness that another engineer can rerun and get the same per-instance pass/fail decisions, plus a manifest that names every pinned artifact and a short regression analysis of the instances where the learner's agent failed.

The reference answer has five deliverables:

1. A **slice declaration** — the subset of SWE-bench (Lite, Verified, or a committed id list) the run is against, with checksum, size, and rationale for the slice.
2. A **pinned harness environment** — a committed `environment.yaml` or `requirements.txt` pinning the SWE-bench harness version, Python version, Docker runtime, and (if applicable) image digests.
3. A **patch-generation pipeline** — the agent config, decoding parameters, context tools, and the exact commands that turn one instance into one `.patch` file; the learner is free to use their agent of choice as long as the pipeline is deterministic given the seed.
4. A **scored artifact tree** — one `predictions.jsonl` with the agent's patches, one `report.json` emitted by the harness scoring run, and one `run.yaml` manifest tying the two together.
5. A **regression table** — one row per failed instance with the harness-reported failure category (patch_failed_to_apply, test_errored, test_failed, timeout, etc.) and a one-line dominant-cause note from the learner. A row saying "flaky" without evidence is not a valid entry.

This maps to the NIST AI RMF `MEASURE` function, which asks that metrics be "repeatable, with documented tools" and reported against an "identified operational context" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)) — a SWE-bench number without the harness version, Docker digest, slice id list, and Python version is a rumor. The adversarial lens is OWASP ML Top 10 **ML06 Corrupted Packages** (every per-task environment pip-installs dependencies; a floating base image or an unpinned transitive turns the eval into a random walk) and **ML09 Output Integrity Attacks** (a patch that passes by deleting the tests is a successful attack on the eval, not on the bug) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS describes the exact techniques the sandbox denies: `Execution: Command and Scripting Interpreter` is every `pytest` invocation; `Impact: Resource Hijacking` is the fork-bomb case a per-task container must bound ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Directory layout

```
swebench_repro/
  README.md
  environment/
    requirements.txt              # pinned pip graph for the harness side
    python_version                # e.g. "3.11.9" (committed as a plain file for easy diff)
  slice/
    slice_v1.txt                  # one instance_id per line
    slice_v1.sha256
  predictions/
    run_2026-11-20/
      predictions.jsonl           # one row per instance with the agent's patch
      agent.log                   # stdout of the patch-generation pipeline
  scoring/
    run_2026-11-20/
      report.json                 # harness-emitted; see schema in §2.5
      REPORT.md                   # human-facing summary + regression table
      run.yaml                    # manifest: harness version, docker runtime, slice SHA, seed
  harness/
    __init__.py
    make_predictions.py           # agent glue; writes predictions.jsonl
    gate.py                       # re-reads report.json; enforces ship/no-ship
  tests/
    test_predictions_shape.py     # schema of predictions.jsonl
    test_gate_logic.py            # pass/fail counting matches report.json
```

Rule: **patches, logs, and the harness report are committed**. The agent is non-deterministic in general; the harness is not. Committing the patch means a reviewer can rerun the scoring without re-paying for the agent.

### 2.2 Slice declaration

The published SWE-bench variants give you three starting points, each with a different tradeoff; pick one and record *which*:

- **SWE-bench Lite** — small, cheap enough to run without heroic infra, intended for quick iteration.
- **SWE-bench Verified** — human-curated subset where the instance is reliably solvable with the provided context; this is the subset most production reports use because the ground truth is not in question.
- **SWE-bench (full)** — the full set; necessary for apples-to-apples with published numbers that use the full set.

<!-- Verify-before-quoting: exact SWE-bench variant sizes and licenses at the harness version pinned in environment/requirements.txt — confirm against the published dataset card before quoting absolute counts in `REPORT.md`. -->

A committed `slice/slice_v1.txt` is the single source of truth for which instance ids the run covers:

```
django__django-11099
django__django-11133
astropy__astropy-7336
sympy__sympy-13757
...
```

Checksum (`slice/slice_v1.sha256`):

```
<sha256>  slice_v1.txt
```

Rules:

- **The slice is explicit.** A "random 30%" without the id list is not reproducible. The committed id list is.
- **Slice rationale is in the README.** "`slice_v1` is 50 Verified instances, uniformly sampled over repositories, selected to fit a 2-hour laptop run; not intended to beat the leaderboard" prevents a later reader from quoting this number as if it were the full-set result.
- **No cherry-picking.** A slice selected after inspecting agent outputs is not a benchmark; it is a reporting artifact. Freeze the slice before running.

### 2.3 Pinned harness environment

The SWE-bench harness is itself a Python package (`swebench`) installed with pinned dependencies. Commit `environment/requirements.txt`:

```
swebench==<version>
<any other pins the harness needs>
```

<!-- Verify-before-pinning: current PyPI package name and latest stable version of the SWE-bench harness — the package name and version string above are placeholders; verify against the project's README before pinning. -->

Commit `environment/python_version` with a single interpreter version (CPython 3.11.x works for recent harness versions; pin a specific patch release so an OS upgrade on the runner does not flip the environment).

The harness builds **per-task Docker images** on first run (and caches them on later runs). Two things to pin here are in Docker's hands:

- **Base-image digest.** The harness's per-task images derive from a committed base; a floating `:latest` upstream tag is a moving target. Record the base image digest in `run.yaml` (§2.5).
- **Runtime.** `docker`, `podman`, or a managed runtime. Record which, and the version (`docker version --format '{{.Server.Version}}'`). Different runtimes have different defaults for `memory-swap` and `pids-limit`; the harness does not fully normalize these.

What **not** to do:

- Rely on `pip install swebench` in a CI step that does not pin a version.
- Reuse an older `build_logs/` cache from a different harness version — image provenance gets muddled and the next clean run produces different images.
- Run the harness on a machine whose Docker daemon has `userns-remap` or custom seccomp profiles turned on without recording that detail. The harness assumes a vanilla daemon; a non-default config can change which tests pass.

### 2.4 Patch-generation pipeline

The learner's agent is a black box to the harness: the only interface is a `predictions.jsonl` whose shape the harness defines. Each row is one instance-id → one unified diff:

```json
{"instance_id": "django__django-11099", "model_name_or_path": "my-agent-v1", "model_patch": "diff --git a/django/foo/bar.py ...\n@@ ...\n"}
```

The expected columns are `instance_id`, `model_name_or_path`, and `model_patch` (unified-diff text). <!-- Verify-before-committing: confirm the exact predictions.jsonl field names against the pinned harness version — some older harness builds used `prediction` or `patch` instead of `model_patch`. -->

Rules of the patch-generation pipeline:

- **Fetch repo at the correct commit.** The dataset row names a `base_commit`; `git checkout` to exactly that commit before giving the agent any context. A patch against `HEAD` is not comparable to a patch against the frozen commit.
- **Do not show the agent the hidden tests.** The SWE-bench instance has `PASS_TO_PASS` and `FAIL_TO_PASS` test identifiers; those are what the harness runs after applying the patch. They are not in the model prompt. A leaked identifier turns the eval into recall of the leak.
- **Context is bounded.** A SWE-bench repo can be millions of tokens; the agent needs a retrieval or grep strategy. Commit the exact strategy (file picker, grep queries, max files, token cap). An ad-hoc "we tried stuff" is not reproducible.
- **Timeouts per instance.** Record a wall-clock cap per instance (e.g., 20 min); over-cap writes `model_patch: ""` (empty patch, the harness scores it as `patch_failed_to_apply`) rather than silently skipping. A silently skipped instance looks like a passing-eval decision not to count that row.
- **Seed and decoding recorded.** Even if the decoding is `temperature=0.0`, record it; a later rerun under a different seed is an audit trail event.

A sketch `harness/make_predictions.py`:

```python
import json, os, subprocess, pathlib

def make_prediction(instance: dict, workdir: pathlib.Path, agent) -> dict:
    repo_url = f"https://github.com/{instance['repo']}.git"
    commit = instance["base_commit"]
    repo_dir = workdir / instance["instance_id"]
    subprocess.run(["git", "clone", "--quiet", repo_url, str(repo_dir)], check=True)
    subprocess.run(["git", "-C", str(repo_dir), "checkout", "--quiet", commit], check=True)

    # Agent: read issue, navigate repo, propose unified diff.
    # The patch MUST apply against `commit`.
    patch = agent.propose_patch(
        issue_text=instance["problem_statement"],
        hints=instance.get("hints_text", ""),
        repo_path=repo_dir,
        timeout_s=1200,
    )

    return {
        "instance_id": instance["instance_id"],
        "model_name_or_path": agent.id,
        "model_patch": patch or "",
    }


def main(dataset_jsonl, slice_txt, out_jsonl, agent):
    wanted = set(pathlib.Path(slice_txt).read_text().split())
    with open(dataset_jsonl) as f_in, open(out_jsonl, "w") as f_out:
        for line in f_in:
            inst = json.loads(line)
            if inst["instance_id"] not in wanted:
                continue
            row = make_prediction(inst, pathlib.Path("/tmp/swebench_work"), agent)
            f_out.write(json.dumps(row) + "\n")
```

### 2.5 Harness scoring + report

With a committed `predictions.jsonl` and the pinned environment active, invoke the harness in the documented way. The exact CLI name has changed across SWE-bench versions; **copy the invocation from the pinned harness's README into `run.yaml`'s `cli:` field** rather than memorize a form that may have moved.

Conceptually, the harness does the same thing on every version:

1. Parses `predictions.jsonl`, keyed by `instance_id`.
2. For each instance, builds (or reuses from cache) a per-task Docker image.
3. Applies `model_patch` to the pinned base_commit inside the container.
4. Runs the instance's `PASS_TO_PASS` + `FAIL_TO_PASS` tests.
5. Emits a per-instance verdict (`resolved: true/false`) and a category (patch applied, patch failed to apply, timeout, test errored, test failed).

The harness emits a `report.json` whose shape is roughly:

```json
{
  "schema_version": "<pinned>",
  "total_instances": 50,
  "resolved": 14,
  "unresolved": 36,
  "by_category": {
    "patch_failed_to_apply": 7,
    "test_errored": 5,
    "test_failed": 24,
    "timeout": 0
  },
  "per_instance": [
    {
      "instance_id": "django__django-11099",
      "resolved": true,
      "category": "resolved",
      "duration_s": 48.2,
      "harness_version": "<pinned>",
      "image_digest": "sha256:<digest>"
    }
  ]
}
```

<!-- Verify-before-committing: the exact `report.json` schema and field names for the pinned harness version — verify against the harness source before committing the schema above into CI expectations. -->

Commit `scoring/run_2026-11-20/report.json` verbatim. Do not post-process it before committing; a reviewer must be able to diff two reports as-emitted.

### 2.6 Run manifest

`scoring/run_2026-11-20/run.yaml`:

```yaml
run_id: swebench_verified_slice_v1_myagent_2026-11-20
slice:
  file: ../../slice/slice_v1.txt
  sha256: <hex>
  size: 50
  variant: verified         # verified | lite | full
  rationale: "50 instances, uniform over repos, selected pre-run; 2 h laptop budget."
harness:
  package: swebench
  version: <pinned>
  cli: "python -m swebench.harness.run_evaluation --predictions_path ../../predictions/run_2026-11-20/predictions.jsonl --max_workers 4 --run_id run_2026-11-20"
runtime:
  python: "3.11.9"
  docker: "<daemon-version>"
  docker_userns_remap: false
  seccomp: default
agent:
  id: my-agent-v1
  model: claude-opus-4-7
  decoding:
    temperature: 0.0
    max_tokens: 4096
  seed: 20261120
  per_instance_timeout_s: 1200
  retrieval:
    kind: "ripgrep + file picker"
    max_files_shown: 15
    max_tokens_of_context: 48000
results:
  resolved: 14
  total: 50
  resolved_rate: 0.28
  by_category:
    patch_failed_to_apply: 7
    test_errored: 5
    test_failed: 24
    timeout: 0
```

Rules:

- **`cli:` is the verbatim command.** A later rerun pastes it; no "then set this flag." If the flags change, bump the manifest filename (`run_2026-11-21.yaml`) and link it from the report.
- **`resolved_rate` is the headline.** Not "accuracy," not "pass@1" — this is the published metric name; keep it so cross-run comparisons search cleanly.
- **Slice rationale in the manifest.** The slice `variant` and `rationale` prevent a `resolved_rate: 0.28` on a 50-instance Verified slice from being compared with a published `0.28` on the full 2k-instance set.

### 2.7 Regression table

`scoring/run_2026-11-20/REPORT.md`:

```
# SWE-bench reproduction — slice_v1 — 2026-11-20

Variant: Verified (slice of 50)
Agent: my-agent-v1 @ claude-opus-4-7, temperature=0.0, seed=20261120
Harness: swebench==<pinned>; Docker <daemon>; Python 3.11.9

## 1. Headline

resolved_rate = 14 / 50 = 0.28

| category                  | count | share |
|---------------------------|-------|-------|
| resolved                  |    14 |  0.28 |
| patch_failed_to_apply     |     7 |  0.14 |
| test_errored              |     5 |  0.10 |
| test_failed               |    24 |  0.48 |
| timeout                   |     0 |  0.00 |

## 2. Regression table (per unresolved instance)

| instance_id                 | category               | dominant cause (one line)                                                        |
|-----------------------------|------------------------|----------------------------------------------------------------------------------|
| django__django-11099        | test_failed            | Agent patch fixed the symptom path; the regression test exercises a sibling path.|
| astropy__astropy-7336       | patch_failed_to_apply  | Patch targeted file renamed between agent's view of HEAD and the base_commit.    |
| sympy__sympy-13757          | test_errored           | Patch introduced an ImportError in a module the hidden test imports first.       |
| ...                         | ...                    | ...                                                                              |

## 3. Known limitations of this run

- Context cap of 48k tokens drops large repos' tests/ directory in favor of src/. Repos where the fix lives in tests/ are disadvantaged. Pre-committed tradeoff.
- Per-instance wall-clock cap of 20 min. Instances timing out are counted as `patch_failed_to_apply` with an empty patch; this is a design choice, not a bug.
- `slice_v1` is a 50-instance Verified slice; numbers here are NOT a proxy for the full SWE-bench Verified leaderboard and should not be quoted as such.

## 4. Files

- `predictions.jsonl` — 50 rows, one per instance.
- `report.json` — harness output, unmodified.
- `run.yaml` — the manifest for this run.
- `agent.log` — pipeline stdout.
```

Rules of the regression table:

- **One row per unresolved instance.** A table that bins by category and quotes category totals is already in §1; this table is for the engineering review.
- **"Dominant cause" is a one-line claim, not a paragraph.** A reviewer should be able to skim 36 rows in 5 minutes. If the claim needs a paragraph, open a tracked issue and link it from the row.
- **"Flaky" is not a valid cause.** The harness is deterministic given the pinned environment. If a rerun flips a verdict, the instance is a candidate for exclusion with a justification, not a note.

## 3. Validation steps

1. **Slice checksum.** `sha256sum -c slice/slice_v1.sha256` passes. CI rejects a drift between `slice_v1.txt` and `slice_v1.sha256`.
2. **Predictions schema.** Every row in `predictions.jsonl` has non-empty `instance_id`, `model_name_or_path`, and (string) `model_patch`; `instance_id` ∈ committed slice; no duplicates.
3. **Patch apply dry-run.** For each row with non-empty `model_patch`, `git apply --check` succeeds against the frozen base_commit in a clean clone. An instance whose patch cannot even dry-apply is a predictable `patch_failed_to_apply`; surfacing it before the full harness run saves hours on first iteration.
4. **Rerun determinism (scoring).** Running the harness twice against the same `predictions.jsonl` with the same pinned env produces byte-identical `report.json` on `per_instance[].resolved` and `category`. Durations may vary; verdicts must not.
5. **Rerun determinism (patching).** Running the patch-generation pipeline twice with the same seed and the same frozen base_commit list produces byte-identical `predictions.jsonl` on `instance_id → model_patch`. If not, name the source of non-determinism in `run.yaml.agent.notes` (e.g., "model backend is not deterministic at temperature=0").
6. **Gate parity.** `harness/gate.py` recomputes `resolved_rate` and by-category counts from `report.json`; CI compares to `run.yaml.results` and rejects a mismatch. A manifest whose numbers disagree with the harness's own report is lying.
7. **Variant honesty.** When `slice.variant == "lite"` or a committed sub-slice of Verified, the report explicitly disclaims that the number is not a full-set rate. CI greps `REPORT.md` for one of a committed set of disclaimer phrases.
8. **No hidden-test leakage.** A grep over `agent.log` and the agent's prompt log asserts that no `PASS_TO_PASS` or `FAIL_TO_PASS` identifier string appears. If the agent is reading the dataset row, filter the identifiers before showing it.
9. **Base-image digest pinned.** `run.yaml.runtime.base_image_digest` is a `sha256:...` form; a `:tag` form is rejected. A floating base image is the single most common reason a rerun's numbers drift by 1–3 instances.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a reproducible, replayable benchmark run**, not the best resolved_rate.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Slice is a committed id list with a checksum and a rationale | 1 | `slice/slice_v1.txt`, `slice/slice_v1.sha256`, `README.md` variant + rationale. |
| R2 | Harness environment pins swebench version, Python version, Docker runtime | 2 | `environment/requirements.txt`, `environment/python_version`, `run.yaml.runtime`. |
| R3 | `predictions.jsonl` committed and schema-validated | 1 | `tests/test_predictions_shape.py`; CI runs on every PR. |
| R4 | `report.json` committed as emitted by the harness, unmodified | 1 | CI diffs committed `report.json` against `jq -S .` of the same file. |
| R5 | Run manifest captures slice SHA, harness version, agent id + decoding + seed, CLI | 2 | `run.yaml` has every field; dry-rerun via `cli:` is a one-liner. |
| R6 | REPORT regression table has one row per unresolved instance with a one-line cause | 1 | `REPORT.md §2` has `count(unresolved)` rows; no "flaky" without evidence. |
| R7 | Headline is labeled `resolved_rate` on the published slice variant with a disclaimer where appropriate | 1 | `REPORT.md §1` names the variant and slice size; disclaimer present when not full-set. |
| R8 | Hidden-test identifiers never appear in the agent's prompt or log | 1 | CI greps `PASS_TO_PASS` / `FAIL_TO_PASS` strings out of `agent.log`. |

**Passing bar:** 7 / 10. R2 and R8 are non-negotiable — a run without a pinned harness/env is not reproducible, and a run with leaked test identifiers is not measuring what it claims to measure.

Reviewer checklist:

- [ ] `swebench` version in `requirements.txt` matches `run.yaml.harness.version`.
- [ ] `slice_v1.txt` size equals `run.yaml.slice.size` equals `report.json.total_instances`.
- [ ] `resolved_rate` in `run.yaml.results` equals `report.json.resolved / report.json.total_instances`.
- [ ] Every `category` in `report.json.by_category` is a known harness category; no "unknown."
- [ ] `git apply --check` passes for every non-empty `model_patch` against the frozen `base_commit`.
- [ ] Rerun of the harness over the same predictions produces the same `per_instance[].resolved`.
- [ ] REPORT disclaims when the slice is not the full published set.
- [ ] No `PASS_TO_PASS` / `FAIL_TO_PASS` identifier appears in `agent.log` or the agent's prompt artifacts.

## 5. Common mistakes

- **Quoting a slice number as the published rate.** "We got 0.28 on SWE-bench Verified" when the run used a 50-instance sample is a reporting bug. Name the slice; add the disclaimer.
- **Unpinned `swebench`.** `pip install swebench` in a CI step without `==<version>` will update between runs; two months later you cannot explain why a 0.27 run became a 0.24 run.
- **Patch against HEAD, not `base_commit`.** The dataset gives you a frozen commit; the hidden tests expect the patch to apply there. Patching HEAD at the time of the agent's view is a guaranteed `patch_failed_to_apply`.
- **Showing the agent the hidden test identifiers.** A `FAIL_TO_PASS` identifier leaks the exact test file path; a motivated agent will inspect that test and reverse-engineer the fix. Strip the identifiers before you pass the instance row to the agent.
- **Silently skipping instances that time out.** Skipping drops the denominator; two runs with different timeout thresholds are not comparable. Empty-patch-on-timeout keeps the denominator stable.
- **Patch that deletes the regression tests.** `rm tests/test_regression.py` passes any `FAIL_TO_PASS` test, by making them undefined. Some harness versions catch this; many do not. Add a pre-score lint that rejects any patch touching the test files named in the instance's `test_patch`.
- **Re-emitting `report.json`.** Pretty-printing or sorting keys for readability breaks a later byte-diff. Commit it as emitted.
- **Running without `--max_workers` matched to the host.** Default concurrency on a 128-core box runs the per-task containers in parallel and OOMs the machine; the harness reports the ones that crashed as `test_errored` and the next rerun with half the workers shows different numbers. Pin `--max_workers` in `cli:`.
- **Base image by `:latest` tag.** Upstream Python base images rev; your "same run" one month later isn't. Pin the base image by `@sha256:...`.
- **Treating `patch_failed_to_apply` as "agent's fault."** It often is, but it is also the signal that the retrieval strategy showed the agent the wrong file version. Split the regression column by this when it is the dominant category.
- **Reporting a resolved_rate without the slice composition.** Two slices of the same size with different repo distributions (one repo heavy on django, another on astropy) score very differently; the number alone is misleading. The manifest's `slice.variant` and `slice.rationale` are not optional.
- **Not committing `agent.log`.** The log is where a reviewer sees that retrieval showed the right file. Without it, every regression table row is a claim without evidence.
- **Mixing predictions from multiple agents.** A `predictions.jsonl` whose `model_name_or_path` varies across rows is scoring an ensemble, not an agent. One agent per predictions file; ensembles get their own manifest.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires metrics and tools to be documented and tied to operational context; the slice id list, the pinned harness version, the committed `report.json`, and the regression table are the direct operationalization for a SWE-bench run.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML06 Corrupted Packages** is the risk per-task Docker images accept on every run; pinning the base image digest and the harness version is the direct mitigation. **ML09 Output Integrity Attacks** motivates the "patch cannot delete the regression tests" lint — a patch that passes by removing the oracle is an integrity attack on the eval.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Execution: Command and Scripting Interpreter` describes what every per-task `pytest` invocation is; `Impact: Resource Hijacking` describes the fork-bomb / OOM surface a per-task container must bound. Running the harness on a vanilla Docker daemon with default seccomp (recorded in `run.yaml`) is the direct control.

<!-- Local exercise context: the specific slice size (50), resolved_rate (0.28), and the `my-agent-v1` identifier are illustrative defaults for a 2-hour laptop-budget run against a Verified sub-slice. Rewrite them to match the learner's actual run; most importantly, do not quote these numbers as if they were full-set SWE-bench Verified results. Agent trajectory scoring and budget tracking (what the agent did during a run, as opposed to whether the hidden tests pass) are covered in [exercise-01](../exercise-01-trajectory-scorer-with-budget-tracking/SOLUTION.md). The web-browsing end-to-end benchmarks (WebArena / GAIA) are the subject of [exercise-03](../exercise-03-webarena-or-gaia-run/SOLUTION.md). Partial-credit rubrics for multi-step tasks (rather than the binary pass/fail SWE-bench uses) are audited in [exercise-04](../exercise-04-partial-credit-rubric-audit/SOLUTION.md). The Inspect agent-eval idioms that wrap a reproduction like this one are in [exercise-05](../exercise-05-inspect-agent-eval-end-to-end/SOLUTION.md). -->
