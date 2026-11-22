# exercise-01 — Trajectory Scorer With Budget Tracking — Solution

## 1. Solution overview

Agent evals cannot be scored like single-turn text evals. A single-turn eval scores one output; an agent eval scores a **trajectory** — the full sequence of (plan, tool call, observation) triples the agent produces between the task and the final answer. Two independent failure modes have to be caught at once:

- **Outcome failure** — the final answer is wrong, or the side effect the task required (a file written, an issue filed, a form submitted) did not happen.
- **Trajectory failure** — the agent reached the right outcome by burning 40 tool calls, 120 k tokens, or $4 of spend, or by calling a tool outside the allowed set. A correct answer at 40× the budget is not a passing run.

This exercise asks the learner to build a **trajectory scorer** that produces a per-episode record capturing both dimensions, plus a **budget tracker** that enforces token / dollar / step / wall-clock ceilings during the run and marks episodes as `over_budget` when a ceiling is hit.

The reference answer has five deliverables:

1. A **trajectory schema** — the on-disk JSONL shape for one episode, including every tool call, its arguments, the observation returned, token counts, dollar cost, and the terminal status.
2. A **budget tracker** — a small Python class that accumulates spend across a run, raises `BudgetExceeded` the moment a ceiling is crossed, and attributes the crossing to a specific step so the trajectory record is not ambiguous.
3. A **trajectory scorer** — a function that reads one trajectory and emits a per-episode score with explicit sub-metrics (outcome, tool_choice, efficiency, budget) so later aggregation does not collapse them into a vibe score.
4. A **test suite** — pinned properties of the tracker and the scorer: double-counting, race conditions between steps, budget attribution, over-budget scoring.
5. A **run manifest** — model id, decoding config, tool registry version, budget ceilings, seed, and the exact CLI; the row another engineer can rerun.

This maps directly to the NIST AI RMF `MEASURE` and `MANAGE` functions: `MEASURE` requires metrics that are "tested, documented, and tied to an identified operational context," and `MANAGE` requires risk management decisions (the ceilings, the override policy) to be documented and tied to a named decision maker ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML09 Output Integrity Attacks** — an agent whose tool calls are not captured on the trajectory can silently rewrite state; and the broader **supply-chain / resource-exhaustion** risks that a missing budget invites ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS names the techniques: `Execution: Command and Scripting Interpreter` (every tool call is one) and `Impact: Resource Hijacking` (an agent without a budget ceiling is a resource-exhaustion surface) ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Directory layout

```
trajectory_eval/
  README.md
  schemas/
    trajectory.schema.json       # JSON Schema for one episode
  harness/
    __init__.py
    budget.py                    # BudgetTracker + BudgetExceeded
    tool_registry.py             # allowed tool names + cost coefficients
    scorer.py                    # trajectory → EpisodeScore
    runner.py                    # glue: dataset → agent → trajectory → scorer
  trajectories/
    run_2026-11-20/
      episodes.jsonl             # one line per episode
      run.yaml                   # manifest
      scores.jsonl               # one line per EpisodeScore
  tests/
    test_budget.py
    test_scorer.py
    fixtures/
      ok_short.json
      ok_long_over_budget.json
      wrong_outcome.json
      disallowed_tool.json
```

Rule: **the raw trajectory is the artifact**, not the aggregate score. A score can be recomputed from a trajectory; a trajectory cannot be recomputed from a score. The `episodes.jsonl` file is what a reviewer loads a month later to answer "why did this run fail?"

### 2.2 Trajectory schema

One JSON object per episode:

```json
{
  "episode_id": "ep-00042",
  "task_id": "tsk-shopping-cart-07",
  "status": "ok",
  "status_reason": null,
  "final_answer": "Order placed, confirmation CF-9318.",
  "ground_truth": {
    "expected_side_effect": "order_placed",
    "accepted_answer_regex": "^Order placed, confirmation \\S+$"
  },
  "steps": [
    {
      "step_index": 0,
      "role": "plan",
      "content": "Need to search catalog for 'noise-cancelling headphones' under $200.",
      "tokens_in": 412, "tokens_out": 58,
      "dollars": 0.00123
    },
    {
      "step_index": 1,
      "role": "tool_call",
      "tool": "catalog.search",
      "arguments": {"query": "noise cancelling headphones", "max_price": 200},
      "tokens_in": 0, "tokens_out": 42,
      "dollars": 0.00018,
      "latency_ms": 184
    },
    {
      "step_index": 2,
      "role": "tool_result",
      "tool": "catalog.search",
      "result_summary": "[{sku: 'HP-14', price: 189}, {sku: 'HP-22', price: 149}]",
      "result_bytes": 612,
      "latency_ms": 0,
      "dollars": 0.0
    }
  ],
  "budget": {
    "tokens_in_total": 2_130,
    "tokens_out_total": 410,
    "dollars_total": 0.0162,
    "wall_clock_s": 7.8,
    "steps_total": 11,
    "ceilings": {
      "tokens_total": 16_000,
      "dollars_total": 0.25,
      "wall_clock_s": 60.0,
      "steps_total": 30
    },
    "crossed": null
  },
  "tool_registry_version": "tools-v3",
  "model": "claude-opus-4-7",
  "decoding": {"temperature": 0.0, "max_tokens": 1024},
  "seed": 20261120
}
```

Four invariants to enforce in CI:

- `status ∈ {ok, wrong_answer, over_budget, disallowed_tool, tool_error, stuck}`. A missing / free-text status defeats downstream filtering.
- Every `tool_call` row names a tool that appears in the committed `tool_registry.tools-v3.json`. A trajectory that invokes an un-registered tool is itself a finding, not a valid run.
- `budget.*_total` fields are **monotone**: for `i < j`, the cumulative values at step `i` are ≤ the cumulative values at step `j`. CI verifies this on load; a non-monotone series means the tracker was reset or double-subtracted.
- `budget.crossed` is non-null exactly when `status == "over_budget"`, and names the first ceiling that was crossed (`tokens_total | dollars_total | wall_clock_s | steps_total`) and the step index where it crossed. "Over budget with no attribution" is a bug.

### 2.3 Budget tracker (`harness/budget.py`)

```python
"""Budget tracker for agent trajectories.

A single tracker instance belongs to one episode. It accumulates token /
dollar / step / wall-clock spend, raises BudgetExceeded the moment a ceiling
is crossed, and attributes the crossing to a specific step so the
trajectory record is not ambiguous."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class BudgetExceeded(Exception):
    """Raised at the exact step that crosses a ceiling.

    The attributes name which ceiling and the cumulative total at the crossing
    so the trajectory can record (ceiling_name, crossing_step, crossing_value)
    verbatim."""

    def __init__(self, ceiling_name: str, crossing_value: float, step_index: int):
        self.ceiling_name = ceiling_name
        self.crossing_value = crossing_value
        self.step_index = step_index
        super().__init__(
            f"budget ceiling '{ceiling_name}' crossed at step {step_index} "
            f"with cumulative value {crossing_value}"
        )


@dataclass(frozen=True)
class Ceilings:
    tokens_total: int
    dollars_total: float
    wall_clock_s: float
    steps_total: int


@dataclass
class BudgetTracker:
    ceilings: Ceilings
    _tokens_in: int = 0
    _tokens_out: int = 0
    _dollars: float = 0.0
    _steps: int = 0
    _started_at: float | None = None
    _crossed: tuple[str, float, int] | None = field(default=None)

    def start(self) -> None:
        if self._started_at is not None:
            raise RuntimeError("BudgetTracker already started")
        self._started_at = time.monotonic()

    def record_step(
        self,
        *,
        tokens_in: int,
        tokens_out: int,
        dollars: float,
        step_index: int,
    ) -> None:
        """Accumulate one step and raise BudgetExceeded if any ceiling crosses.

        Called exactly once per step (plan / tool_call / tool_result all count
        as individual steps). The caller writes the step to the trajectory
        BEFORE calling record_step so that an exception still produces a row.
        """
        if self._started_at is None:
            raise RuntimeError("BudgetTracker.start() was not called")
        if self._crossed is not None:
            # Defensive: the runner must stop on the first BudgetExceeded; a
            # second record_step would double-count a crossing.
            raise RuntimeError("BudgetTracker already crossed a ceiling")

        self._tokens_in += tokens_in
        self._tokens_out += tokens_out
        self._dollars += dollars
        self._steps += 1

        total_tokens = self._tokens_in + self._tokens_out
        wall = time.monotonic() - self._started_at

        # Check in a deterministic order so attribution is stable across runs.
        for name, value, ceiling in (
            ("tokens_total", total_tokens, self.ceilings.tokens_total),
            ("dollars_total", self._dollars, self.ceilings.dollars_total),
            ("wall_clock_s", wall, self.ceilings.wall_clock_s),
            ("steps_total", self._steps, self.ceilings.steps_total),
        ):
            if value > ceiling:
                self._crossed = (name, float(value), step_index)
                raise BudgetExceeded(name, float(value), step_index)

    def snapshot(self) -> dict:
        wall = 0.0 if self._started_at is None else (time.monotonic() - self._started_at)
        return {
            "tokens_in_total": self._tokens_in,
            "tokens_out_total": self._tokens_out,
            "dollars_total": round(self._dollars, 6),
            "wall_clock_s": round(wall, 3),
            "steps_total": self._steps,
            "ceilings": {
                "tokens_total": self.ceilings.tokens_total,
                "dollars_total": self.ceilings.dollars_total,
                "wall_clock_s": self.ceilings.wall_clock_s,
                "steps_total": self.ceilings.steps_total,
            },
            "crossed": (
                None
                if self._crossed is None
                else {
                    "ceiling": self._crossed[0],
                    "value": self._crossed[1],
                    "step_index": self._crossed[2],
                }
            ),
        }
```

Design rules worth calling out:

- **One tracker per episode.** A shared tracker across episodes lets one task consume the next one's budget and makes the per-episode `over_budget` label meaningless.
- **Check in a fixed order.** Tokens before dollars before wall-clock before steps. If two ceilings cross on the same step, the attribution is stable across runs; otherwise two reruns with identical trajectories report different ceilings and nobody can diff them.
- **Monotonic clock.** `time.monotonic()` instead of `time.time()`: a wall-clock NTP step mid-run must not retroactively re-attribute a ceiling.
- **Raise immediately, don't wait for the step to finish.** The runner catches `BudgetExceeded`, finalizes the trajectory with `status="over_budget"` and `budget.crossed=...`, and stops. A tracker that only reports post-hoc lets the agent continue past the ceiling.

### 2.4 Trajectory scorer (`harness/scorer.py`)

```python
"""Trajectory scorer: one trajectory JSON object in, one EpisodeScore out.

The scorer DOES NOT re-run the agent; it only reads what the runner wrote.
Scoring is deterministic given the trajectory, which is the property that
makes a trajectory a first-class artifact: re-score with a new rubric
without re-paying for inference."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class EpisodeScore:
    episode_id: str
    outcome: float          # 0 or 1
    tool_choice: float      # 0..1
    efficiency: float       # 0..1
    budget: float           # 0 or 1 (1 = stayed within ceilings)
    status: str             # mirror of trajectory.status
    notes: str


def score_episode(trajectory: dict, allowed_tools: set[str]) -> EpisodeScore:
    status = trajectory["status"]
    budget = 1.0 if status != "over_budget" else 0.0

    # Outcome: exact match (regex on the accepted_answer_regex), OR side-effect
    # match. If the ground_truth declares both, both must hold.
    gt = trajectory.get("ground_truth") or {}
    answer_ok = True
    if "accepted_answer_regex" in gt:
        answer_ok = bool(
            re.fullmatch(gt["accepted_answer_regex"], trajectory.get("final_answer") or "")
        )
    side_effect_ok = True
    if "expected_side_effect" in gt:
        # Runner is responsible for turning observed side-effect checks into a
        # dedicated step with role='side_effect_check'; see runner.py.
        side_effect_ok = any(
            s.get("role") == "side_effect_check"
            and s.get("name") == gt["expected_side_effect"]
            and s.get("result") == "pass"
            for s in trajectory["steps"]
        )
    outcome = 1.0 if (answer_ok and side_effect_ok and status == "ok") else 0.0

    # Tool choice: 1 if every tool_call is in the allowed set; 0 otherwise.
    tool_calls = [s for s in trajectory["steps"] if s.get("role") == "tool_call"]
    tool_choice = (
        1.0
        if all(s.get("tool") in allowed_tools for s in tool_calls)
        else 0.0
    )

    # Efficiency: per-task floor divided by observed steps. Floors are
    # declared on the task; a task with no floor scores efficiency=1 iff
    # outcome==1 and 0 otherwise (don't invent an unprincipled floor).
    task_floor = (trajectory.get("ground_truth") or {}).get("min_tool_calls")
    observed_calls = len(tool_calls)
    if task_floor is None:
        efficiency = outcome
    else:
        if observed_calls == 0:
            efficiency = 0.0
        else:
            efficiency = min(1.0, task_floor / observed_calls)

    notes = _notes(status, trajectory, answer_ok, side_effect_ok, tool_calls, allowed_tools)
    return EpisodeScore(
        episode_id=trajectory["episode_id"],
        outcome=outcome,
        tool_choice=tool_choice,
        efficiency=efficiency,
        budget=budget,
        status=status,
        notes=notes,
    )


def _notes(status, trajectory, answer_ok, side_effect_ok, tool_calls, allowed_tools) -> str:
    bits = []
    if status != "ok":
        bits.append(f"status={status}")
    if not answer_ok:
        bits.append("regex-mismatch")
    if not side_effect_ok:
        bits.append("side-effect-missing")
    disallowed = [s.get("tool") for s in tool_calls if s.get("tool") not in allowed_tools]
    if disallowed:
        bits.append(f"disallowed={sorted(set(disallowed))}")
    crossed = (trajectory.get("budget") or {}).get("crossed")
    if crossed:
        bits.append(f"over-budget@{crossed['ceiling']}")
    return "; ".join(bits) if bits else "ok"
```

Why four separate sub-metrics instead of one scalar:

- `outcome` is a product metric — did the task succeed.
- `tool_choice` catches the "right answer by wrong means" case (the agent reached a disallowed tool; the side effect it produced is a liability).
- `efficiency` catches the "right answer at 10× the cost" case; the per-task floor is the contract.
- `budget` catches hard ceiling crossings separately from everything else; it is the single metric that cannot be gamed by better prompting.

**Averaging these four into one scalar is forbidden.** Each is a veto on shipping. Report per-metric; a pass = `outcome ∧ tool_choice ∧ budget` and `efficiency ≥ gate`.

### 2.5 Tool registry (`harness/tool_registry.py`)

```python
"""Tool registry: the committed list of tools the agent may call, with the
cost coefficients used by the runner to attribute dollars per call.

The registry is versioned as a whole (tools-v3); a change to a tool's
signature or price bumps the version. An episode's trajectory records the
registry version it ran against so a reviewer can diff two eras."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    dollars_per_call: float
    dollars_per_kb_result: float
    description: str


REGISTRY_V3: dict[str, ToolSpec] = {
    "catalog.search": ToolSpec(
        "catalog.search", 0.0001, 0.0, "Search the product catalog."
    ),
    "catalog.get_sku": ToolSpec(
        "catalog.get_sku", 0.0001, 0.0, "Fetch one SKU detail by id."
    ),
    "cart.add": ToolSpec("cart.add", 0.0001, 0.0, "Add a SKU to the cart."),
    "cart.view": ToolSpec("cart.view", 0.0001, 0.0, "View the cart contents."),
    "order.place": ToolSpec(
        "order.place", 0.001, 0.0, "Place an order from the current cart."
    ),
}


def allowed_tool_names(version: str) -> set[str]:
    if version != "tools-v3":
        raise ValueError(f"unknown registry version: {version}")
    return set(REGISTRY_V3)
```

The registry does **not** execute tools; it only pins their names and cost coefficients. A real tool lives behind the same interface (one function per tool) and is loaded by the runner against the committed version. A registry-version bump is a semver event: the manifest in §2.7 records the version so two runs can be compared only when the version matches.

### 2.6 Runner integration (sketch, `harness/runner.py`)

```python
from harness.budget import BudgetTracker, BudgetExceeded, Ceilings
from harness.tool_registry import allowed_tool_names

def run_episode(task, model, tools, ceilings) -> dict:
    tracker = BudgetTracker(ceilings=ceilings)
    tracker.start()
    steps: list[dict] = []
    status = "ok"
    status_reason = None
    final_answer = None

    try:
        for step_index, step in enumerate(model.run(task, tools)):
            steps.append(step)                      # write FIRST so an exception still has a row
            tracker.record_step(
                tokens_in=step.get("tokens_in", 0),
                tokens_out=step.get("tokens_out", 0),
                dollars=step.get("dollars", 0.0),
                step_index=step_index,
            )
            if step["role"] == "tool_call" and step["tool"] not in allowed_tool_names("tools-v3"):
                status = "disallowed_tool"
                status_reason = f"called {step['tool']!r}"
                break
            if step["role"] == "final":
                final_answer = step["content"]
                break
    except BudgetExceeded as e:
        status = "over_budget"
        status_reason = f"{e.ceiling_name}={e.crossing_value}"

    return {
        "episode_id": task["episode_id"],
        "task_id": task["task_id"],
        "status": status,
        "status_reason": status_reason,
        "final_answer": final_answer,
        "ground_truth": task["ground_truth"],
        "steps": steps,
        "budget": tracker.snapshot(),
        "tool_registry_version": "tools-v3",
        "model": model.id,
        "decoding": model.decoding,
        "seed": task.get("seed"),
    }
```

Two properties the runner must preserve:

- **Write-then-record.** Append the step to `steps` *before* calling `tracker.record_step`. A `BudgetExceeded` is not supposed to erase the step that caused it.
- **One termination point.** The loop exits on three events: budget crossed, disallowed tool, or `role == "final"`. A fourth exit (silent model stop, hung tool) is a bug; the runner raises on it and the episode gets `status="stuck"` so it is not silently averaged into a pass number.

### 2.7 Run manifest

Commit `trajectories/run_2026-11-20/run.yaml`:

```yaml
run_id: shopping_v1_opus-4-7_2026-11-20
task_set: shopping_v1
task_set_sha256: <sha256 of tasks/shopping_v1.jsonl>
tool_registry_version: tools-v3
harness_commit: <git sha>
model:
  id: claude-opus-4-7
  decoding:
    temperature: 0.0
    max_tokens: 1024
budget_ceilings:
  tokens_total: 16000
  dollars_total: 0.25
  wall_clock_s: 60.0
  steps_total: 30
budget_rationale:
  tokens_total: "p95 of a 200-item pilot was 12.4k; 16k gives 25% headroom."
  dollars_total: "$0.25 is the per-episode cap product set for the shopping skill."
  wall_clock_s: "User-perceivable response time ceiling from the product spec."
  steps_total: "Pilot tasks solved in <= 20 steps; 30 is a hard stop, not a goal."
seed: 20261120
cli: "python -m harness.runner --tasks tasks/shopping_v1.jsonl --ceilings run.yaml --out trajectories/run_2026-11-20/"
aggregates:
  outcome_rate: 0.78
  tool_choice_rate: 1.00
  efficiency_mean: 0.74
  budget_passed_rate: 0.92
  pass_rate: 0.72   # outcome ∧ tool_choice ∧ budget
```

The numeric ceilings are declared **with a rationale**. A ceiling with no rationale is a magic number; the first reviewer who wants to loosen it has no principled basis and will loosen it until it passes. The rationale pins the "why" so a later rerun that drifts over the ceiling opens a conversation, not a silent threshold bump.

## 3. Validation steps

1. **Schema conformance.** Every `episodes.jsonl` row validates against `schemas/trajectory.schema.json` (status enum, budget shape, `crossed` attribution). CI fails a run whose log does not validate.
2. **Monotone budget check.** For every episode, the cumulative `tokens_total`, `dollars_total`, `wall_clock_s`, and `steps_total` are non-decreasing along `steps`. A failure means the tracker was reset mid-episode or a step double-subtracted.
3. **Budget attribution.** For every episode with `status="over_budget"`, `budget.crossed` is non-null; the named ceiling is one of the four; the `step_index` points at a real step; and the cumulative value at that step exceeds the ceiling. CI rejects otherwise.
4. **Deterministic scorer.** Running `python -m harness.scorer --in episodes.jsonl --out scores.jsonl` twice produces byte-identical outputs. The scorer must not read anything outside the trajectory (clock, env, network).
5. **Pinned fixtures.** `tests/fixtures/` contains four hand-authored trajectories (`ok_short`, `ok_long_over_budget`, `wrong_outcome`, `disallowed_tool`) and `tests/test_scorer.py` asserts every sub-metric and `status` on each. Any change to the scorer must preserve these assertions.
6. **Tracker property tests.** `tests/test_budget.py` covers:
   - a zero-step run has `wall_clock_s >= 0` and no crossings;
   - crossing `tokens_total` by 1 at step `k` sets `crossed=("tokens_total", total, k)`;
   - a tracker cannot be started twice; `record_step` after a crossing raises;
   - ceiling order is stable: if two ceilings cross on the same step, `tokens_total` wins.
7. **Reproducibility.** Rerun of `cli` with the same `task_set_sha256`, model id, `seed`, and `tool_registry_version` produces `episodes.jsonl` whose per-episode `status`, `final_answer`, and `budget.steps_total` are identical to the first run.
8. **Aggregate sanity.** `aggregates.pass_rate` equals the fraction of episodes with `outcome==1 ∧ tool_choice==1 ∧ budget==1`. CI recomputes from `scores.jsonl` and compares to the manifest; a mismatch rejects the run as internally inconsistent.
9. **Registry-version pin.** Every episode's `tool_registry_version` matches the manifest's. A mixed-version run is rejected — a trajectory recorded against `tools-v2` is not comparable to one recorded against `tools-v3`.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a replayable record, not just an accuracy number**.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | One JSONL row per episode with the committed schema | 1 | `trajectory.schema.json` + CI validator; every row passes. |
| R2 | `status` is a closed enum and `over_budget` attributions name a ceiling and step | 2 | Fixtures cover every enum value; attribution object is non-null iff `status=="over_budget"`. |
| R3 | BudgetTracker raises at the crossing step with a stable ceiling order | 2 | `test_budget.py` pins ordering; `monotonic` clock; one-shot tracker. |
| R4 | Scorer emits sub-metrics (outcome, tool_choice, efficiency, budget) separately | 2 | `EpisodeScore` dataclass; CI forbids a single-scalar aggregate. |
| R5 | Tool registry is versioned; trajectory records the version | 1 | `tool_registry_version` field matches manifest; CI rejects mismatch. |
| R6 | Manifest pins model, decoding, seed, ceilings, registry version, CLI | 1 | `run.yaml` has every field; rerun with same inputs reproduces per-episode results. |
| R7 | Ceiling values have a committed rationale | 1 | `budget_rationale.*` present for every ceiling; none is a magic number. |

**Passing bar:** 7 / 10. R3 and R4 are non-negotiable — without stable budget attribution the `over_budget` label is a rumor, and without separate sub-metrics the pass decision can be averaged past a disallowed-tool call.

Reviewer checklist:

- [ ] `status` is one of the committed enum values on every row.
- [ ] `budget.crossed` is non-null exactly when `status == "over_budget"`.
- [ ] Monotone-budget check passes on every episode.
- [ ] Scorer is deterministic given the trajectory (two runs byte-identical).
- [ ] Sub-metrics are reported and AND-ed; no single-scalar pass decision.
- [ ] `tool_registry_version` matches the manifest on every row.
- [ ] Ceilings have a numeric value and a rationale; no `TODO`.
- [ ] Reruns with the same seed produce the same per-episode `status`, `final_answer`, and `budget.steps_total`.
- [ ] A disallowed tool in any step yields `status="disallowed_tool"` or `tool_choice=0`, not a silent pass.

## 5. Common mistakes

- **Scoring only the final answer.** A one-shot answer check hides "right answer via disallowed tool," "right answer at 10× cost," and "right answer after side-effect-level accidents." Score the trajectory; aggregate sub-metrics.
- **Shared tracker across episodes.** Reusing one `BudgetTracker` across tasks makes the first episode consume ceiling room meant for the next one. One tracker per episode.
- **Budget check after the step.** Recording spend but only checking ceilings at the end of the episode lets the agent continue 10 steps past the cap. Check inside `record_step`; raise immediately.
- **Non-deterministic ceiling attribution.** A set / dict iteration order is implementation-detail; two Python versions can report different crossings on the same trajectory. Check in a committed order.
- **Dollars computed from token counts post-hoc.** A pricing change retroactively alters past trajectories' dollar columns. Record the dollar at the step; the pricing coefficient is a registry field, not a spreadsheet lookup.
- **Writing the step after recording spend.** The step that crosses the budget is exactly the one worth seeing on the trajectory; writing after `record_step` loses it on the raise. Append-then-record.
- **Ceilings with no rationale.** `tokens_total: 100000` with no context loosens the moment the eval fails. Commit a one-line rationale per ceiling.
- **Scoring with a floor the task does not declare.** An efficiency score computed against an implicit floor ("agents should solve in 5 steps") penalizes tasks whose optimal plan is 7. Put the floor on the task; score against it.
- **Averaging sub-metrics into one scalar.** A score of `0.75 = 0.6 outcome + 0.9 tool_choice + 0.75 efficiency + budget`. The one failure that matters (an unauthorized tool) is drowned by two easy wins. AND the sub-metrics for the pass decision.
- **Tool registry drift without a version bump.** Adding `payments.refund` to the registry between two runs silently changes what "disallowed" means. Bump the registry version; record it on every trajectory.
- **`time.time()` for wall clock.** NTP step mid-run can retroactively re-attribute a wall-clock ceiling to the wrong step. Use `time.monotonic()`.
- **Silent "stuck" counted as "ok".** The model loop exits without a `final` step; the runner records no status and the episode counts toward the pass rate. Make `stuck` a committed status; raise on an un-terminated run.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires metrics and their test harness to be tested, documented, and tied to an operational context; the committed trajectory schema, versioned tool registry, and per-ceiling rationale are the direct operationalization for an agent eval. The `MANAGE` function requires documented, owned risk decisions; the budget ceilings' committed rationale is the ownership trail.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** motivates recording every tool call and observation on the trajectory, not just the final answer; without the trajectory, an agent silently writing to state via an un-registered tool is invisible.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Execution: Command and Scripting Interpreter` describes what each tool call is; `Impact: Resource Hijacking` describes the resource-exhaustion surface an un-bounded agent opens. The versioned registry and the raising budget tracker are the two direct controls.

<!-- Local exercise context: the shopping-cart task family, the specific tools (`catalog.search`, `order.place`, etc.), the ceiling values (16k tokens, $0.25, 60 s, 30 steps), and the registry version string `tools-v3` are illustrative defaults for a small e-commerce agent eval. Rewrite them for the task family, cost model, and user-perceivable latency budget of your own agent before adopting. The SWE-bench reproduction case (code-editing agents against pinned repos) is covered in [exercise-02](../exercise-02-swe-bench-reproduction/SOLUTION.md); the WebArena / GAIA browsing case is covered in [exercise-03](../exercise-03-webarena-or-gaia-run/SOLUTION.md); the partial-credit rubric audit that the sub-metrics above feed into is the subject of [exercise-04](../exercise-04-partial-credit-rubric-audit/SOLUTION.md); the Inspect framework's agent-eval idioms that wrap this harness are in [exercise-05](../exercise-05-inspect-agent-eval-end-to-end/SOLUTION.md). -->
