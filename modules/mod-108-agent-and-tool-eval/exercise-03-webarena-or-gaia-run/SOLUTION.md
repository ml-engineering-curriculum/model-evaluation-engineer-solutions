# exercise-03 — WebArena or GAIA Run — Solution

## 1. Solution overview

Web-browsing agent evals are not "benchmarks you install" — they are infrastructure. WebArena ships a self-hostable set of containerised web applications (an e-commerce site, a collaborative wiki, a code-forge, a classifieds site, a map) and tasks whose success is checked by programmatic predicates against those apps' back-end state. GAIA ships a public question set and a private leaderboard; the task text is public, the ground-truth answer is not, and your submission is scored by the leaderboard's grader. The two benchmarks solve different measurement problems and have different reproducibility traps; this exercise asks the learner to pick one, run it end-to-end, and report the number with enough context that a reviewer can reproduce it.

The reference answer has five deliverables:

1. A **benchmark decision** — WebArena or GAIA, with a one-paragraph rationale that names the operational question the run is trying to answer. A run that cannot name the question is reporting a vanity number.
2. A **pinned environment** — for WebArena, the committed image digests of the five web apps plus the agent-side harness version; for GAIA, the dataset snapshot, the leaderboard submission date, and the agent's harness commit.
3. A **task slice declaration** — the list of task ids, a checksum, a size, and a rationale for the slice (full set, difficulty-balanced subset, or a committed sub-slice). A "we ran some tasks" reporter sentence is not a slice.
4. A **run artifact tree** — `trajectories.jsonl` (one trajectory per task), `scores.jsonl` (per-task verdicts), `run.yaml` (manifest), and either the WebArena programmatic-check log or the GAIA leaderboard-reply payload.
5. A **failure-mode table** — one row per failed task with a committed failure category (login_loop, wrong_entity_selected, state_poisoning, final_answer_wrong_format, timeout, refusal, etc.) and a one-line cause. The headline number is useless without this.

This maps to the NIST AI RMF `MEASURE` function — a web-agent number without the environment snapshot, slice id list, and harness version is a weather report ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML09 Output Integrity Attacks** (an agent that writes to a shared sandbox's state can "pass" a later task by setting up its own fixtures) and the general **supply-chain** surface a browser agent opens (every page the agent fetches is executable content inside the harness's browser) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS names the techniques: `Execution: User Execution` is every click, `Impact: Data Manipulation` is the state-poisoning case the WebArena predicates catch, `Reconnaissance: Search Open Technical Databases` is what a GAIA agent does with every web search ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Which benchmark?

Pick on the question the run is trying to answer:

- **WebArena**: "Can our agent complete a realistic multi-step web task where success is defined by a programmatic predicate over the app's backend state (order placed, repo starred, listing posted)?" Self-hosted. Grader is a function; the grader is not a judge. Reproducible with pinned image digests.
- **GAIA**: "Can our agent answer realistic human questions that require reading a document, searching the web, running code, and composing — in short-answer form that a hidden grader will accept?" Public + private leaderboard. Grader is on a remote server; you submit, you get a score. Reproducible only up to the submission date.

Commit the choice and the rationale in `README.md`. A run against "whichever was easier to install" is not an eval.

Both benchmarks need the following structure. Where they diverge, the sub-sections below name the fork.

### 2.2 Directory layout

```
web_agent_eval/
  README.md                                # which benchmark + rationale
  environment/
    webarena/                              # ONLY if WebArena
      compose.yaml                         # the 5 app services, pinned by @sha256
      pinned_digests.sha256
      reset_fixtures.sh                    # scripted reset to known state
    gaia/                                  # ONLY if GAIA
      dataset_snapshot.jsonl               # task ids + prompts; no answers
      dataset_snapshot.sha256
    harness/
      requirements.txt                     # browser agent + driver pins
  slice/
    slice_v1.txt                           # one task_id per line
    slice_v1.sha256
  runs/
    2026-11-20/
      trajectories.jsonl                   # one row per task
      scores.jsonl                         # one row per task
      run.yaml                             # manifest
      REPORT.md                            # summary + failure-mode table
      webarena_check_log.jsonl             # IF WebArena
      gaia_submission_payload.json         # IF GAIA
      gaia_leaderboard_reply.json          # IF GAIA
```

Rule: **trajectories are the artifact**. A rerun of the scorer against a committed `trajectories.jsonl` should produce the same `scores.jsonl` without re-paying for the agent. The grader is also pinned (WebArena predicate code or GAIA leaderboard snapshot date).

### 2.3 Environment pinning

#### WebArena

Five apps run as containers; the harness drives a browser against them. Everything in `environment/webarena/compose.yaml` is pinned by digest, not tag:

```yaml
# environment/webarena/compose.yaml
services:
  shopping:
    image: <registry>/webarena-shopping@sha256:<digest>
    environment: { ... }
    ports: ["7770:80"]
  shopping_admin:
    image: <registry>/webarena-shopping-admin@sha256:<digest>
    ports: ["7780:80"]
  reddit:
    image: <registry>/webarena-reddit@sha256:<digest>
    ports: ["9999:80"]
  gitlab:
    image: <registry>/webarena-gitlab@sha256:<digest>
    ports: ["8023:80"]
  wikipedia:
    image: <registry>/webarena-wikipedia@sha256:<digest>
    ports: ["8888:80"]
  map:
    image: <registry>/webarena-map@sha256:<digest>
    ports: ["3000:3000"]
```

<!-- Verify-before-use: the exact service list, image names, and port mappings depend on the WebArena version — mirror the project's official compose file at the pinned harness version instead of trusting these placeholders. -->

Rules:

- **Reset between tasks.** WebArena predicates read the app's database; a task that creates an order leaves the order behind. `reset_fixtures.sh` restores each app to its committed baseline (committed SQL dumps or a `docker compose down && docker compose up -d` cycle against a `init.sql` volume). The run script calls it before every task. Without this, task N's result depends on task N-1 and the eval is non-reproducible by construction.
- **No network egress beyond the five apps.** The agent's browser connects to `localhost:7770` / `:8023` / etc. — not to the live internet. A task whose predicate says "the order is placed in the local shopping app" cannot be satisfied by a live Amazon purchase; a browser that reaches out defeats the sandbox. Enforce with `docker network create --internal` (or a per-task firewall rule) and confirm by running one "ping the internet" fixture task; it must fail.
- **Agent's browser is also pinned.** Playwright / Selenium plus a committed Chromium (or a committed browser image). A different browser version renders CSS differently; some WebArena tasks depend on a specific element being visible-to-click.

#### GAIA

GAIA is simpler to host (dataset is a file) and harder to pin (the grader is remote).

- **Dataset snapshot.** Commit the public task JSON as `environment/gaia/dataset_snapshot.jsonl` with a checksum. The upstream dataset moves; a run's numbers are only reproducible against the snapshot the run used.
- **Submission date.** The leaderboard version is implicit in the date of your submission. Record `submission_submitted_at: <ISO 8601>` and `leaderboard_version_observed: <string or hash of the public leaderboard config at submission time>` in the manifest.
- **Agent's tools.** GAIA tasks require web search, code execution, and file reading. Record (a) the exact search provider used (and its snapshot date, because search results move), (b) the exact code-execution sandbox image digest, and (c) the exact OCR / PDF-reader model and version if the agent uses one.

### 2.4 Slice declaration

`slice/slice_v1.txt` is the single source of truth for which tasks the run covers. One task id per line. A checksum file sits next to it.

Rules:

- **Slice before running.** A slice chosen after inspecting agent outputs is a reporting artifact, not a benchmark. Freeze the slice, record the SHA, run the agent.
- **Rationale in README.** "`slice_v1` is a 60-task balanced sample across the five WebArena domains (12 each), selected uniformly at random with `seed=20261120`; not intended to beat the leaderboard." A reader three months later must not be able to misread this as a full-set result.
- **Full set is a valid choice** for the WebArena / GAIA headline run. For iteration runs, slices are fine; label them.

### 2.5 Trajectory capture

A trajectory is one JSON object per task:

```json
{
  "task_id": "wa_shopping_00042",
  "variant": "webarena",
  "status": "ok",
  "status_reason": null,
  "steps": [
    {"step_index": 0, "role": "plan", "content": "Find headphones under $200..."},
    {"step_index": 1, "role": "action", "action": "goto", "arguments": {"url": "http://localhost:7770/"}},
    {"step_index": 2, "role": "observation", "observation_summary": "Homepage loaded (title: 'OneStopMarket')"},
    {"step_index": 3, "role": "action", "action": "fill", "arguments": {"selector": "input[name=search]", "value": "noise cancelling headphones"}},
    ...
    {"step_index": 42, "role": "final", "content": "Order placed, confirmation CF-9318."}
  ],
  "model": "claude-opus-4-7",
  "decoding": {"temperature": 0.0, "max_tokens": 2048},
  "seed": 20261120,
  "wall_clock_s": 94.3,
  "steps_total": 43,
  "tokens_in_total": 48_210,
  "tokens_out_total": 3_104,
  "dollars_total": 0.37
}
```

Properties worth noting:

- **Action schema is a closed enum.** The committed action set (`goto`, `click`, `fill`, `scroll`, `keyboard_press`, `tab.new`, `tab.switch`, `terminate`) means a diffing tool can tell you how two trajectories diverged. An open-ended action string prevents that.
- **Observations are summaries, not full DOMs.** Committing the full DOM per step bloats the artifact and leaks any dynamic content that may rev between runs. A summary ("element X became visible," "URL changed to Y," "alert dialog appeared") is enough for a reviewer.
- **Final answer / termination is explicit.** WebArena tasks terminate by calling a `terminate` or `stop` action with a final answer (or by the harness's time cap); GAIA tasks terminate when the agent emits a short answer. Either way, the trajectory has a single `role=final` entry.
- **Budget columns.** `wall_clock_s`, `steps_total`, `tokens_*`, `dollars_total` — these line up with the schema from [exercise-01](../exercise-01-trajectory-scorer-with-budget-tracking/SOLUTION.md); a WebArena run reuses the same trajectory scorer.

### 2.6 Scoring

#### WebArena

The WebArena grader is **a programmatic predicate per task**, committed with the benchmark. Example predicates (paraphrased from the task set's shape):

- `shopping`: "order with sku X and quantity Y was placed by user `test1@example.com`."
- `gitlab`: "project `foo/bar`'s README contains the string `Contributor: ...`."
- `reddit`: "a submission with title `...` exists in subreddit `sub-A`."

The grader queries the app's backend (or runs a scripted check against the UI) **after** the agent terminates and before the next task's reset. It returns `{"pass": true/false, "predicate": "<id>", "evidence": "<JSON>"}`.

A WebArena run's scorer is thin:

```python
def score_webarena(trajectory: dict, predicate_fn) -> dict:
    # The predicate is pinned by the benchmark version; it reads live app state.
    verdict = predicate_fn(task_id=trajectory["task_id"])
    return {
        "task_id": trajectory["task_id"],
        "pass": bool(verdict["pass"]),
        "predicate": verdict["predicate"],
        "evidence": verdict["evidence"],
        "trajectory_status": trajectory["status"],
    }
```

Rules:

- **Grader runs against live state.** It reads the actual app DB (e.g. `select count(*) from orders where ...`). It is not a model-graded step; it is a committed query.
- **Grader sees post-trajectory state only.** The predicate is evaluated once, right after termination, right before reset. A mid-trajectory check that "latches" a passing state and then the agent breaks it would flip the result; keep the check post-hoc.
- **State-poisoning is a trajectory-status.** An agent that, on task N, also modifies state that task N+1 assumes is clean is doing OWASP ML09 against the eval. The reset-before-every-task rule denies this.

#### GAIA

The GAIA grader is **remote**. The learner submits the final answers; the leaderboard returns pass/fail.

A GAIA run's scorer wraps the submission:

```python
def score_gaia(trajectory_batch: list[dict]) -> dict:
    submission = {
        "submission_id": "<uuid>",
        "answers": [
            {"task_id": t["task_id"], "final_answer": _final(t)}
            for t in trajectory_batch
        ],
        "submitted_at": "<ISO 8601>",
    }
    # submit to leaderboard...
    reply = submit(submission)
    # reply is {"task_id": ..., "pass": bool, "category": "..."} per task
    return reply
```

Rules:

- **Submit once per `slice_v1` run.** The leaderboard rate-limits; submitting the same slice twice an hour to patch typos is a reporting bug. Fix the bug, bump the slice to `slice_v2`, resubmit.
- **Commit the submission payload AND the reply.** `gaia_submission_payload.json` + `gaia_leaderboard_reply.json`. A future reader can diff "what we submitted" from "what the grader returned," which is the only artifact that survives the grader moving.
- **Do not store ground-truth answers.** GAIA's private answers are intentionally not public. A trajectory committed in-repo must not include the leaderboard's ground truth even if you obtain it through a confirmation page. Keep only the grader's pass/fail.

### 2.7 Run manifest

`runs/2026-11-20/run.yaml`:

```yaml
run_id: webarena_slice_v1_myagent_2026-11-20
variant: webarena                    # or: gaia
slice:
  file: ../../slice/slice_v1.txt
  sha256: <hex>
  size: 60
  rationale: "Balanced 60-task sample across five WebArena domains; pre-run freeze."
environment:
  webarena_compose_sha256: <hex>     # sha of compose.yaml (which pins by digest)
  webarena_reset_scheme: "docker compose down -v && docker compose up -d && reset_fixtures.sh"
  # for GAIA:
  # gaia_snapshot_sha256: <hex>
  # gaia_submission_submitted_at: "2026-11-20T18:04:22Z"
  # gaia_leaderboard_version_observed: "<string>"
harness:
  package: <learner's harness>
  version: <pinned>
  cli: "python -m harness.runner --variant webarena --slice slice/slice_v1.txt --out runs/2026-11-20/"
agent:
  id: my-agent-v1
  model: claude-opus-4-7
  decoding: {temperature: 0.0, max_tokens: 2048}
  seed: 20261120
  tools:
    browser: "playwright==<pinned>; chromium@<digest>"
    # for GAIA:
    # search: "<provider>@<snapshot-date>"
    # code_exec: "<image>@sha256:<digest>"
budget_ceilings:
  wall_clock_s: 300
  steps_total: 60
  dollars_total: 1.00
results:
  pass_rate: 0.38
  passes: 23
  total: 60
  by_domain:                         # WebArena
    shopping: {pass: 6, total: 12}
    gitlab:   {pass: 5, total: 12}
    reddit:   {pass: 4, total: 12}
    wikipedia:{pass: 7, total: 12}
    map:      {pass: 1, total: 12}
  # for GAIA:
  # by_level: {1: {pass: ..., total: ...}, 2: ..., 3: ...}
```

Rules:

- **`cli:` is the verbatim invocation.** A reviewer should be able to paste it and rerun.
- **`by_domain` / `by_level` are reported alongside the headline.** A `pass_rate: 0.38` that is 1 / 12 on the map domain and 7 / 12 on wikipedia is a different signal than one that is 4 / 12 on everything. The breakdown is not optional.

### 2.8 Failure-mode table

`runs/2026-11-20/REPORT.md`:

```
# WebArena reproduction — slice_v1 — 2026-11-20

Variant: WebArena
Slice: 60 tasks, balanced across 5 domains
Agent: my-agent-v1 @ claude-opus-4-7, temperature=0.0, seed=20261120
Harness: <pinned>

## 1. Headline
pass_rate = 23 / 60 = 0.38

| domain     | pass | total |
|------------|------|-------|
| shopping   |    6 |    12 |
| gitlab     |    5 |    12 |
| reddit     |    4 |    12 |
| wikipedia  |    7 |    12 |
| map        |    1 |    12 |

## 2. Failure-mode table (per failing task)

| task_id             | domain    | category                 | dominant cause (one line)                                         |
|---------------------|-----------|--------------------------|-------------------------------------------------------------------|
| wa_map_00014        | map       | wrong_entity_selected    | Agent clicked a visually similar POI 2 blocks east.               |
| wa_reddit_00009     | reddit    | login_loop               | Submit-form path tried to log in a user already authenticated.    |
| wa_gitlab_00031     | gitlab    | state_poisoning_prior    | Prior task left the repo with a non-default branch; reset lag.    |
| wa_shopping_00017   | shopping  | final_answer_wrong_format| Agent placed the order but answer prose mentioned wrong SKU.      |
| ...                 | ...       | ...                      | ...                                                               |

## 3. Known limitations
- Budget ceiling is 300 s wall-clock per task; map tasks are at the ceiling (12 / 12 ran to timeout). Not a model-quality signal on that domain for this run.
- Reset scheme is `docker compose down -v`; this is ~60 s between tasks. Any task whose fixture depends on another task's state will fail; the single `state_poisoning_prior` failure indicates one stale reset, not a benchmark design flaw.
- `slice_v1` is NOT the full WebArena set; numbers here are not directly comparable to published full-set results.

## 4. Files
- trajectories.jsonl
- scores.jsonl
- run.yaml
- webarena_check_log.jsonl
```

Rules of the table:

- **One row per failing task.** Passing tasks do not get a row; they are summarized in §1.
- **`category` is a closed enum.** Commit the enum (`login_loop`, `wrong_entity_selected`, `final_answer_wrong_format`, `refusal`, `state_poisoning_prior`, `timeout`, `browser_crash`, `grader_rejected`, `other`). "Other" is a drop-dead category for an in-review post-mortem.
- **"Dominant cause" is one line.** If you can't fit it on one line, open a tracked issue and link it from the row.

## 3. Validation steps

1. **Slice checksum.** `sha256sum -c slice/slice_v1.sha256` passes.
2. **Image digest audit (WebArena).** Every `image:` in `compose.yaml` is pinned by `@sha256:...`; no `:tag`. CI greps for a `@sha256:` match.
3. **Isolation check.** With the compose stack up and the agent launched against a one-task "ping the internet" fixture, the task fails (because egress is denied). If it passes, the sandbox is leaking.
4. **Reset-between-tasks.** A two-task smoke run where task A creates an order and task B asserts "orders is empty" on the same app must have task B pass. If it fails, the reset is not happening.
5. **Grader determinism (WebArena).** Rerunning the predicates against the same post-trajectory state produces the same `pass`. The predicate is pure; the state is what rev'd.
6. **Determinism of the run (WebArena).** Rerunning the agent with the same seed against the reset fixtures produces `scores.jsonl` identical on `task_id → pass`. If not, name the non-determinism source in `run.yaml.agent.notes` (usually: model backend).
7. **Grader snapshot (GAIA).** The committed `gaia_leaderboard_reply.json` matches the submission_id in `gaia_submission_payload.json`. CI rejects a reply whose submission_id doesn't line up.
8. **No ground truth in-repo (GAIA).** A grep rejects any key in `trajectories.jsonl` or `scores.jsonl` whose name matches `ground_truth` / `expected_answer` / `correct_answer`. The learner has only pass/fail from the leaderboard.
9. **Headline matches breakdown.** `pass_rate × total == sum(by_domain[*].pass)`. CI asserts arithmetic.
10. **Budget ceilings respected.** No trajectory exceeds `budget_ceilings.*`. If it does, `status == "over_budget"` (see [exercise-01](../exercise-01-trajectory-scorer-with-budget-tracking/SOLUTION.md)) and it counts as a fail, not as "didn't try."
11. **Enum closure.** Every row in the failure-mode table has a `category` in the committed enum.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a reproducible run with contextualized numbers**, not the highest pass_rate.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Benchmark choice documented with a one-paragraph rationale | 1 | `README.md §1`. |
| R2 | Environment pinned (WebArena: image digests + reset; GAIA: snapshot + submission date) | 2 | `compose.yaml` only uses `@sha256:`; `environment/gaia/dataset_snapshot.sha256` matches; `submission_submitted_at` present. |
| R3 | Slice is a committed id list with checksum and rationale | 1 | `slice/slice_v1.txt`, `slice/slice_v1.sha256`, README rationale. |
| R4 | Trajectories captured with a closed action schema and non-DOM observations | 2 | `trajectories.jsonl` conforms; a sampled row renders readably. |
| R5 | Scoring is grader-sourced (WebArena predicate log / GAIA leaderboard reply), not re-derived | 1 | Committed `webarena_check_log.jsonl` or `gaia_leaderboard_reply.json`; `scores.jsonl` matches. |
| R6 | REPORT has a breakdown (domain for WebArena / level for GAIA), not just a headline | 1 | `REPORT.md §1` has the breakdown table; arithmetic check passes. |
| R7 | Failure-mode table has one row per failure with a committed-enum category | 1 | `REPORT.md §2`; CI asserts enum closure. |
| R8 | Sandbox denies egress (WebArena) or no ground truth stored in-repo (GAIA) | 1 | `ping-the-internet` smoke fails; grep finds no ground-truth keys. |

**Passing bar:** 7 / 10. R2 and R5 are non-negotiable — a run without a pinned grader-source and a pinned environment is not reproducible.

Reviewer checklist:

- [ ] Every image in `compose.yaml` is pinned by digest (WebArena).
- [ ] Every row in `scores.jsonl` has a `pass: bool` and a matching entry in the grader's own log.
- [ ] `pass_rate` in the manifest equals `passes / total` and equals the sum over `by_domain[*].pass`.
- [ ] Reset between tasks is scripted and tested with a two-task smoke run.
- [ ] Failure-mode table has one row per failure; no "other" without a linked issue.
- [ ] Budget ceilings have numeric values and the trajectories respect them.
- [ ] REPORT disclaims when the slice is not the full published set.
- [ ] No ground-truth keys in committed artifacts (GAIA).

## 5. Common mistakes

- **Running without inter-task reset.** Task N poisons task N+1's state and `pass_rate` becomes order-sensitive. Reset is mandatory; the smoke test for the reset is mandatory.
- **Compose pinned by tag, not digest.** A base-image refresh upstream changes CSS; a locator-based agent silently regresses by 10 points. Pin by digest; bump intentionally.
- **Letting the browser reach the real internet.** The agent finds the live site by Googling; it books the real order; the WebArena predicate reads the local DB and fails. Deny egress; the eval is self-contained.
- **Reporting a slice's pass_rate as the published rate.** "0.38 on WebArena" — reader assumes full set. Name the slice; add the disclaimer.
- **Full DOMs on every observation.** The artifact balloons; dynamic content leaks into the diff. Store summaries; keep the raw DOM only on the last screenshot per task if at all.
- **Open-ended action strings.** `"act": "click the third-highest item"` is not reproducible. Commit a closed action enum with a fixed selector shape.
- **Resubmitting GAIA to patch typos.** Rate-limited, gets your submission flagged, and the two `pass_rate` numbers you generate are not comparable anyway (slice snapshot is the same but your batch is different). Fix the bug, bump the slice id, resubmit once.
- **Storing GAIA ground truth in-repo.** Even inferred from the leaderboard reply (right answer by elimination), the ground truth is private. Keep only pass/fail.
- **Grader that uses the same LLM as the agent (GAIA).** You can't choose GAIA's grader; it's remote. But if you add your own grader for WebArena (don't), do not use the model under test to evaluate itself; the number becomes "model's self-assessment," not an eval.
- **Budget ceilings that are too high.** 10-minute wall-clock per task means `map` tasks get 1 / 12 at 10 minutes each; most of the cost is the timeouts. Set a reasonable ceiling for the product the agent will ship into; the ceiling is itself a product property.
- **No `status` on hung tasks.** A task that never terminates is silently dropped; the denominator looks smaller. Hung-after-budget is `status: over_budget`; it counts as a fail.
- **Mixing agents between runs.** A `scores.jsonl` whose `trajectories.jsonl` has a different `model` or `decoding` per row is scoring an ensemble, not an agent. One agent, one run.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires metrics tied to operational context with documented tools; the committed compose digests, the pinned dataset snapshot, the committed slice id list, and the committed grader-source log are the direct operationalization for a web-agent run.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** is the state-poisoning case the WebArena reset-per-task rule denies; the broader supply-chain surface motivates the browser version pin and the egress denial.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Execution: User Execution` describes every click the agent makes; `Reconnaissance: Search Open Technical Databases` is the GAIA agent's whole web-search loop; `Impact: Data Manipulation` is the state-poisoning path the reset denies.

<!-- Local exercise context: the 60-task slice, the `pass_rate: 0.38` number, the by-domain breakdown, and the `my-agent-v1` identifier are illustrative defaults for a 2-hour laptop budget against a balanced WebArena sub-slice. Rewrite them to the actual slice, environment, and run; do not quote these numbers as published WebArena or GAIA results. Trajectory scoring and budget tracking generalities are in [exercise-01](../exercise-01-trajectory-scorer-with-budget-tracking/SOLUTION.md); the SWE-bench code-editing counterpart is in [exercise-02](../exercise-02-swe-bench-reproduction/SOLUTION.md); the partial-credit rubric audit that applies to multi-step web tasks is in [exercise-04](../exercise-04-partial-credit-rubric-audit/SOLUTION.md); the Inspect agent-eval idioms that can wrap a run like this are in [exercise-05](../exercise-05-inspect-agent-eval-end-to-end/SOLUTION.md). -->
