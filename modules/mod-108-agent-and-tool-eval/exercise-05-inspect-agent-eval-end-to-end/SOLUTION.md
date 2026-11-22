# exercise-05 — Inspect Agent Eval End-to-End — Solution

## 1. Solution overview

The UK AI Safety Institute's **Inspect** framework treats an eval as a first-class, replayable artifact: a `@task`-decorated Python function composes a dataset, a solver, and a scorer; a `.eval` log file captures every prompt, every tool call, every tool observation, and every score. For single-turn evals (the mod-104 exercise-03 case) the solver is a short chain of `prompt_template → generate → post_process`. For an **agent** eval, the solver is a loop that gives the model a tool belt, runs the model's chosen tool call, feeds back the observation, and repeats until the model terminates. This exercise asks the learner to build one of those, end to end, with the Inspect idioms rather than a custom harness.

The reference answer has five deliverables:

1. A **task module** — a single `@task` function wiring a dataset, an agent solver, and a scorer.
2. A **tool belt** — at least two Inspect `@tool`-decorated functions with explicit argument schemas and a committed allow-list; the agent is constrained to tools on that list.
3. An **agent solver** — either `use_tools(...)` + `generate()` wired into a loop, or Inspect's higher-level agent solver, with a committed step budget and a stop condition.
4. A **scorer** — a per-item `Score(value, answer, explanation)` that reads the full trajectory from the log and reports both outcome and trajectory-quality sub-metrics.
5. A **run manifest + `.eval` log** — a pinned `inspect_ai` version, a seed, the exact `inspect eval` command, and the committed log that `inspect view` replays.

This maps to the NIST AI RMF `MEASURE` function, which requires measurement to be "repeatable, with documented prompts and tools" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)) — Inspect's `.eval` log and the pinned `@tool` schemas satisfy this directly. The adversarial lens is OWASP ML Top 10 **ML09 Output Integrity Attacks** — the log is the audit trail that catches a solver silently rewriting tool arguments or a scorer silently passing a trajectory that called an un-registered tool ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Execution: Command and Scripting Interpreter` describes what every tool call is; a structured log with per-step argument capture is the defender's control ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Directory layout

```
inspect_agent_eval/
  README.md                        # task description, license, provenance
  pyproject.toml                   # pins inspect_ai and any tool deps
  tasks/
    __init__.py
    shopping_agent.py              # @task + tools + solver + scorer
  tools/
    __init__.py
    catalog.py                     # @tool functions for the mock shopping API
    cart.py
    order.py
  data/
    dev.jsonl                      # ~10 items for smoke tests
    test.jsonl                     # a few dozen items
    checksums.sha256
  runs/
    2026-11-20/
      run.yaml                     # exact CLI + model + seed + tool-registry sha
      results.eval                 # Inspect log, openable with `inspect view`
      REPORT.md                    # summary + CI + regression table
  tests/
    test_tool_contracts.py
    test_scorer_properties.py
```

Rule: **commit the `.eval` log and the manifest together**. The log is the artifact; everything else is recoverable from it or from the committed sources.

### 2.2 Dataset shape

One JSONL row per task; the `metadata` field carries agent-specific ground truth that the scorer reads back:

```json
{
  "id": "sa-00007",
  "input": "Buy a pair of noise-cancelling over-ear headphones under $200 and place the order to the default address.",
  "target": "order_placed",
  "metadata": {
    "allowed_tools": ["catalog_search", "catalog_get_sku", "cart_add", "cart_view", "order_place"],
    "expected_side_effect": "order_placed",
    "accepted_answer_regex": "^Order placed, confirmation \\S+$",
    "min_tool_calls": 3,
    "budget": {"max_steps": 30, "max_dollars": 0.25}
  }
}
```

The `input`/`target` names match Inspect's `Sample` schema so the dataset loader can hand rows straight to the solver. The `metadata` fields (`allowed_tools`, `expected_side_effect`, `accepted_answer_regex`, `min_tool_calls`, `budget`) are what the scorer uses to compute per-item sub-scores; they are not shown to the model.

### 2.3 Tool belt

Each tool lives in its own module, is decorated with `@tool`, and has a docstring the model can read. Argument schemas are **explicit** — Inspect inspects type hints and the docstring to build the tool's JSON schema, which is what the model sees.

`tools/catalog.py`:

```python
from inspect_ai.tool import tool


@tool
def catalog_search():
    """Search the catalog for products matching a query and budget."""

    async def run(query: str, max_price: float | None = None) -> str:
        """Return up to 5 matching SKUs.

        Args:
          query: free-text description of the product.
          max_price: optional dollar cap; omit for no cap.
        """
        # Mock backend; the production tool would call the real catalog.
        from tools._mock_backend import search_catalog
        rows = search_catalog(query=query, max_price=max_price)[:5]
        if not rows:
            return "no matches"
        return "\n".join(f"{r['sku']}\t${r['price']}\t{r['title']}" for r in rows)

    return run


@tool
def catalog_get_sku():
    """Fetch full details for one SKU by id."""

    async def run(sku: str) -> str:
        """Return a short description of the SKU, or 'unknown sku' if missing.

        Args:
          sku: the sku id (e.g. 'HP-14').
        """
        from tools._mock_backend import get_sku
        row = get_sku(sku)
        return "unknown sku" if row is None else f"{row['sku']} ${row['price']} {row['title']} — {row['description']}"

    return run
```

`tools/order.py`:

```python
from inspect_ai.tool import tool


@tool
def order_place():
    """Place an order from the current cart to the default address."""

    async def run() -> str:
        """Return the confirmation string, or an error if the cart is empty.

        Takes no arguments; the backend reads the current cart.
        """
        from tools._mock_backend import place_order
        result = place_order()
        if result.get("error"):
            return f"error: {result['error']}"
        return f"Order placed, confirmation {result['confirmation']}"

    return run
```

Rules the tool belt enforces:

- **Docstrings are measurement surfaces.** Inspect ships the docstring to the model as the tool description. A terse or wrong docstring will show up as a wrong tool call in the log; a model-graded scorer that reads "the model was confused about the tool" is really saying "the docstring is confusing." Edit the docstring; don't downgrade the scorer.
- **Return types are strings by default.** A model consumes strings. A tool that returns a dict is fine — Inspect will stringify it — but the stringified form is the surface the model sees, so make it legible. The format above (`sku\tprice\ttitle`) is compact, parseable, and shows up readably in `inspect view`.
- **No side-effect-bearing tools call live backends.** The `tools/_mock_backend.py` is a deterministic in-process stub. A real deployment hides the mock behind the same Python function signature; the eval harness sets an env flag to force the mock. A test suite that silently reaches out to a live catalog is not reproducible.
- **Tool allow-list per task.** The dataset row's `metadata.allowed_tools` is what the solver registers for that sample. A disallowed tool in the Inspect log is itself a finding; the scorer reports it.

### 2.4 Agent solver

Inspect provides building blocks for agent solvers; the two most useful idioms are `use_tools(...)` + `generate()` wrapped in a loop, or the higher-level `basic_agent()` for the common ReAct pattern. For an exercise, either is fine; the solver below uses `basic_agent()` with explicit stop conditions so the step budget is visible.

`tasks/shopping_agent.py` (abridged):

```python
from inspect_ai import task, Task
from inspect_ai.dataset import json_dataset, Sample
from inspect_ai.solver import (
    basic_agent,
    chain,
    system_message,
    use_tools,
    solver,
    TaskState,
    Generate,
)
from inspect_ai.tool import tool_with
from inspect_ai.scorer import scorer, Score, Target, accuracy, bootstrap_std, mean

from tools.catalog import catalog_search, catalog_get_sku
from tools.cart import cart_add, cart_view
from tools.order import order_place


SYSTEM = """You are a shopping assistant. Use the available tools to complete the
user's request. When the task is done, respond with exactly one line beginning
'Order placed, confirmation <id>' or an explanation if you could not complete.
Do not call tools not provided to you."""


ALL_TOOLS = {
    "catalog_search": catalog_search,
    "catalog_get_sku": catalog_get_sku,
    "cart_add":        cart_add,
    "cart_view":       cart_view,
    "order_place":     order_place,
}


@solver
def register_sample_tools():
    """Register ONLY the tools in the sample's metadata.allowed_tools list."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        allowed = state.metadata["allowed_tools"]
        tools = [ALL_TOOLS[name]() for name in allowed if name in ALL_TOOLS]
        state.tools = tools
        return state
    return solve


@scorer(metrics=[accuracy(), bootstrap_std(), mean()])
def trajectory_scorer():
    """Score outcome + trajectory. Reads the full trajectory from state.messages
    and the task's ground truth from state.metadata.

    Emits sub-scores through Score.answer / Score.explanation so the viewer
    renders them next to each item."""

    async def score(state: TaskState, target: Target) -> Score:
        md = state.metadata
        regex = md["accepted_answer_regex"]
        allowed = set(md["allowed_tools"])
        min_calls = md["min_tool_calls"]

        import re

        # Outcome: last assistant message matches the accepted-answer regex.
        last = state.output.completion or ""
        outcome = bool(re.fullmatch(regex, last.strip()))

        # Tool choice: every tool call is in the allow-list.
        tool_calls = [
            m for m in state.messages if m.role == "tool"
        ]
        disallowed = [
            getattr(m, "tool_name", "") for m in tool_calls
            if getattr(m, "tool_name", "") not in allowed
        ]
        tool_choice_ok = not disallowed

        # Efficiency: observed_calls <= 2 * min_calls.
        observed = len(tool_calls)
        efficiency_ok = observed <= 2 * min_calls

        passed = outcome and tool_choice_ok and efficiency_ok

        explanation = (
            f"outcome={'y' if outcome else 'n'}; "
            f"tool_choice={'y' if tool_choice_ok else f'n({sorted(set(disallowed))})'}; "
            f"efficiency={'y' if efficiency_ok else 'n'} "
            f"(observed={observed}, min={min_calls})"
        )
        return Score(
            value=1.0 if passed else 0.0,
            answer=last.strip()[:80],
            explanation=explanation,
            metadata={
                "outcome": outcome,
                "tool_choice_ok": tool_choice_ok,
                "efficiency_ok": efficiency_ok,
                "observed_tool_calls": observed,
                "disallowed_tool_calls": sorted(set(disallowed)),
            },
        )
    return score


@task
def shopping_agent():
    return Task(
        dataset=json_dataset("data/test.jsonl", sample_fields=Sample),
        solver=chain(
            system_message(SYSTEM),
            register_sample_tools(),
            basic_agent(
                max_messages=30,       # mirrors metadata.budget.max_steps
                # agent terminates when the model emits an assistant message
                # without a tool call, or when max_messages is reached.
            ),
        ),
        scorer=trajectory_scorer(),
    )
```

Notes worth calling out:

- **Per-sample tool registration.** The `register_sample_tools` solver reads `metadata.allowed_tools` and sets `state.tools` before the agent step runs. A single task module scores different samples against different tool allow-lists without branching the task function.
- **`basic_agent(max_messages=30)` is the committed step budget.** A rerun with a different `max_messages` is not comparable; the manifest records this value.
- **`Score.metadata` carries sub-scores.** Inspect shows the top-level `value` for the aggregate, but `metadata.outcome`, `metadata.tool_choice_ok`, `metadata.efficiency_ok` are what a later analysis queries. The `value` is a single bool; the diagnosis is in the metadata.
- **`explanation` is not optional.** The whole point of using Inspect is that `inspect view` opens the log and a human reads each row's explanation. A blank explanation discards the framework's benefit.

### 2.5 Run the eval

```bash
pip install --no-deps 'inspect-ai==<pinned-version>'

inspect eval tasks/shopping_agent.py@shopping_agent \
    --model <vendor>/<model-id> \
    --model-config revision=<commit-sha>,dtype=bfloat16 \
    --seed 20261120 \
    --log-dir runs/2026-11-20/ \
    --limit 50 \
    --max-tokens 1024 \
    --temperature 0.0
```

Flag-by-flag:

- `inspect eval <path>@<fn>` — runs the `@task` function named `<fn>` in `<path>`.
- `--model <vendor>/<model-id>` — selects an Inspect model provider. Pin the provider's identifier here; record the revision via `--model-config` where supported.
- `--seed 20261120` — fixes the sampling RNG; with `temperature=0.0` the eval is deterministic up to the provider's own determinism contract.
- `--log-dir` — writes a `.eval` log file that `inspect view` opens. The log is the artifact; commit it.
- `--limit 50` — keeps iteration cheap; drop the flag for the full pass.

### 2.6 Run manifest

`runs/2026-11-20/run.yaml`:

```yaml
inspect_version: "<pinned>"
task: "tasks/shopping_agent.py@shopping_agent"
model: "<vendor>/<model-id>"
model_revision: "<commit-sha>"
dtype: "bfloat16"
seed: 20261120
max_tokens: 1024
temperature: 0.0
basic_agent_max_messages: 30
dataset:
  path: "data/test.jsonl"
  checksum: "<sha256>"
  item_count: 50
tool_registry:
  module: "tools/"
  sha256: "<sha256 of tools/ directory contents>"
  names: ["catalog_search", "catalog_get_sku", "cart_add", "cart_view", "order_place"]
hardware:
  gpus: "cloud-hosted; provider endpoint"
  cuda: "n/a"
aggregates:
  accuracy: 0.74
  accuracy_bootstrap_std: 0.06
  outcome_rate: 0.80
  tool_choice_rate: 0.96
  efficiency_rate: 0.86
```

The three sub-rates (outcome / tool_choice / efficiency) live alongside the single `accuracy` headline. A reviewer who sees `accuracy: 0.74` and `tool_choice_rate: 0.96` knows the 26 % failure is mostly outcome or efficiency, not disallowed tools — a different diagnosis than a run with `tool_choice_rate: 0.80`, which would mean one-in-five trajectories touched an un-registered tool.

### 2.7 Report shape

`runs/2026-11-20/REPORT.md`:

```
# Inspect agent eval — shopping_agent — 2026-11-20

## 1. Summary
accuracy = 0.74 ± 0.06 (95% bootstrap, 10000 resamples)
outcome_rate = 0.80
tool_choice_rate = 0.96
efficiency_rate = 0.86
items scored = 50 / 50

## 2. Verdict
"Blessed run." OR
"Regression vs. 2026-10-30 (Δaccuracy = −0.04, tolerance = ±0.06). See §4."

## 3. Attachments
- run.yaml
- results.eval   (open with `inspect view --log-dir .`)

## 4. Regression root-cause table (per failed item)
| sample_id   | outcome | tool_choice | efficiency | dominant cause                             |
|-------------|---------|-------------|------------|--------------------------------------------|
| sa-00007    | no      | yes         | yes        | wrong SKU selected; price filter ignored.  |
| sa-00014    | yes     | no          | yes        | agent called `admin_refund` (disallowed).  |
| sa-00021    | yes     | yes         | no         | 9 tool calls vs min 3; agent re-queried.   |
```

The table has one row per failed item; the sub-score columns make the dominant failure obvious without opening the log. Open the log in `inspect view` to walk the trajectory for any suspicious row.

## 3. Validation steps

1. **Dry-run on dev.** `inspect eval ... --limit 10` against `data/dev.jsonl` must complete and produce a non-empty `.eval` log before the full run spends compute.
2. **Log-viewer round-trip.** `inspect view --log-dir runs/<date>/` opens and renders every item's prompt, tool calls, tool observations, final completion, and score explanation. A blank explanation column is a scorer bug.
3. **Dataset checksum.** `sha256sum -c data/checksums.sha256` passes before the `inspect eval` command runs.
4. **Tool contract tests.** `tests/test_tool_contracts.py` asserts: (a) each `@tool` has a non-empty docstring, (b) each `run` is `async def`, (c) each argument has a type hint, (d) `catalog_search("")` returns `"no matches"` on the mock backend. These are the contract between the model and the tool; they do not change on a model swap.
5. **Scorer property tests.** `tests/test_scorer_properties.py` constructs synthetic `TaskState` fixtures covering each sub-score permutation (outcome∧¬tool_choice, outcome∧¬efficiency, etc.) and asserts the scorer's `Score.metadata` matches. Any change to the scorer must preserve these.
6. **No disallowed-tool silent pass.** A fixture task row whose `allowed_tools` omits `order_place` is run against a model that insists on calling `order_place`; the Inspect log records the disallowed call and the scorer reports `tool_choice_ok=false`. If the item nonetheless scores `value=1.0`, the scorer is wrong.
7. **Determinism.** Rerun with the same `seed`, model revision, dataset checksum, and `basic_agent_max_messages`; per-item `Score.value` and `Score.metadata.observed_tool_calls` must match to the digit. If the provider is non-deterministic at `temperature=0.0`, record that in `run.yaml.notes`.
8. **Budget respected.** `basic_agent_max_messages` is honored: `metadata.observed_tool_calls` is ≤ 30 on every item. An item that terminated by hitting the ceiling is not counted as a pass unless the scorer's `efficiency_ok` says so.
9. **Tool-registry SHA pin.** A change to any file under `tools/` changes `run.yaml.tool_registry.sha256`. CI verifies the committed SHA matches a fresh walk of the directory.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the eval being a **replayable, auditable agent eval**, not a one-off notebook.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | A single `@task` function wires dataset + solver + scorer | 1 | `tasks/shopping_agent.py` exports an `@task`-decorated function. |
| R2 | At least two `@tool`-decorated functions with explicit arg types and non-empty docstrings | 2 | `tools/catalog.py`, `tools/order.py`; tool contract tests pass. |
| R3 | Agent solver has a committed step budget (`basic_agent(max_messages=…)` or equivalent) | 1 | Manifest records `basic_agent_max_messages`; CI asserts per-item `observed_tool_calls ≤ budget`. |
| R4 | Tool allow-list is per-sample and enforced by the solver | 1 | `register_sample_tools()` reads `metadata.allowed_tools`; disallowed-tool test fails an item that touches a missing tool. |
| R5 | Scorer emits Score with `value`, `answer`, `explanation`, and sub-score `metadata` | 2 | `inspect view` renders explanation and metadata; CI rejects a blank explanation. |
| R6 | `.eval` log committed alongside `run.yaml` | 1 | `runs/<date>/results.eval` + `run.yaml` are in the repo. |
| R7 | Manifest pins inspect version, model revision, seed, max_messages, tool_registry sha | 1 | `run.yaml` has every field; rerun with same inputs reproduces per-item scores. |
| R8 | Report has a per-failure table with sub-score columns | 1 | `REPORT.md §4` has one row per failed item; dominant cause is a one-liner. |

**Passing bar:** 7 / 10. R4 and R5 are non-negotiable — without allow-list enforcement the eval cannot distinguish "agent solved the task" from "agent solved it by calling an admin tool," and without `Score.metadata` sub-scores the headline is uninspectable.

Reviewer checklist:

- [ ] `inspect view --log-dir runs/<date>/` opens and renders every item cleanly.
- [ ] No tool call in the log has an argument shape the tool's type hint rejects.
- [ ] Every item's `Score.explanation` names outcome / tool_choice / efficiency verdict.
- [ ] A rerun with the pinned inputs produces identical `Score.value` per item.
- [ ] Disallowed-tool fixture item scores `value=0.0` with `metadata.disallowed_tool_calls` populated.
- [ ] `basic_agent_max_messages` in the manifest matches the solver source.
- [ ] Tool-registry SHA in the manifest matches a fresh walk of `tools/`.
- [ ] REPORT regression table has one row per failure; no "other" without a linked issue.
- [ ] Headline `accuracy` is reported with its bootstrap CI; sub-rates are reported alongside.

## 5. Common mistakes

- **`basic_agent()` with a default `max_messages`.** The default varies across Inspect versions; two runs across an upgrade report different numbers because the agent took more turns. Pin `max_messages` explicitly in the task and the manifest.
- **A single global tool belt.** Registering all tools for every sample means the `allowed_tools` metadata is an aspirational note. Use a per-sample `register_sample_tools` solver (or equivalent) so the model physically does not see tools it may not call.
- **Tool docstring is a 2-word description.** The docstring is the model's documentation. "Searches." is not a tool spec; "Search the catalog for products matching a query and budget. Args: query (str), max_price (float|None)." is.
- **Live backend inside a tool.** A tool that calls a production catalog on every `catalog_search` is non-reproducible and leaks eval load into prod metrics. Mock the backend; bind to live via a feature flag in deployment, never in eval.
- **Scorer doesn't read `state.messages`.** Scoring only `state.output.completion` throws away the trajectory. The viewer's audit value is the per-step detail; a scorer that ignores it pays for Inspect and uses none of it.
- **`Score.value` is a weighted sum of sub-scores.** Collapsing outcome + tool_choice + efficiency into `0.3 + 0.4 + 0.3` lets a disallowed-tool run score 0.7. Keep `value` binary; put sub-scores in `metadata`; let the reporter decide which to present.
- **Using the production system prompt.** A `SYSTEM` string that was tuned for the product on top of the eval tends to mention tools, success criteria, or format hints that bias the eval. Commit a dedicated eval system prompt; diff it against the product's.
- **Not pinning `inspect-ai`.** Solver / tool / scorer APIs evolve; a notebook that worked last month may behave differently on an upgrade. `==<version>` in `pyproject.toml`.
- **Reusing a log directory across runs.** Inspect appends to a log dir; two runs in one dir make the "which run produced this number" question unanswerable. One dir per run, dated.
- **No budget on tool calls.** An agent without `max_messages` can loop forever; your eval is now a wall-clock game. Commit a max; items that hit it are failures, not errors.
- **Scoring only the terminal message's regex.** A model that emits "Order placed, confirmation ..." without having called `order_place` passes the regex but did nothing. Check the trajectory for the required side-effect tool call; score outcome only when both regex and side-effect checks pass (see [exercise-01](../exercise-01-trajectory-scorer-with-budget-tracking/SOLUTION.md)'s side-effect-check step).
- **`observed_tool_calls` computed by counting the string "tool" in the log.** The `state.messages` list is the structured source. A string-count breaks the moment Inspect rev's the message types; the structured iterator does not.
- **Writing tools that return large payloads.** A `catalog_search` that returns 5 kB per call pushes the context window toward the budget ceiling on long trajectories, and the agent's efficiency drops artifact-ly. Return compact representations; keep the detail behind a `catalog_get_sku(sku)` second call.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires measurement to be repeatable and documented; Inspect's `.eval` log is the measurement artifact that satisfies the requirement for an agent eval, and the pinned `@tool` schemas are the documented interface the model was measured against.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** motivates keeping the full trajectory — not just the final completion — in the log and scoring from it. A silent tool-argument rewrite inside a solver is exactly the integrity failure the log is designed to surface.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Execution: Command and Scripting Interpreter` describes what every agent tool call is; Inspect's structured capture of (tool_name, arguments, observation) per step is the defender's direct control, replayable with `inspect view`.

<!-- Local exercise context: the shopping-agent task family, the specific mock tools (`catalog_search`, `order_place`, etc.), the 50-item slice, and the sub-score numbers (accuracy 0.74, tool_choice 0.96) are illustrative defaults for a small agent eval against a mock e-commerce backend. Rewrite them for the agent task-family and tool belt you actually evaluate. The trajectory schema and budget-tracker that this Inspect scorer mirrors are in [exercise-01](../exercise-01-trajectory-scorer-with-budget-tracking/SOLUTION.md); the code-fixing agent case (SWE-bench) that uses binary pass/fail instead of trajectory sub-scores is in [exercise-02](../exercise-02-swe-bench-reproduction/SOLUTION.md); the web-browsing agent benchmarks are in [exercise-03](../exercise-03-webarena-or-gaia-run/SOLUTION.md); the partial-credit rubric design that wraps a scorer like this one is in [exercise-04](../exercise-04-partial-credit-rubric-audit/SOLUTION.md). The single-turn Inspect eval pattern that this exercise extends to agents is covered in `mod-104/exercise-03-inspect-eval-end-to-end`. -->
