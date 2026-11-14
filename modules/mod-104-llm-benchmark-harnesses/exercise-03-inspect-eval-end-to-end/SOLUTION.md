# exercise-03 — Build an Inspect Eval End-to-End — Solution

## 1. Solution overview

The exercise asks the learner to build a complete evaluation using the UK AI Safety Institute's **Inspect** framework: dataset loader, solver pipeline, scorers, and a reproducible run that emits an Inspect log the viewer can open. Unlike lm-evaluation-harness (which centers a declarative task YAML), Inspect centers a **Python-first task function** that composes a `Solver` pipeline and a `Scorer`, and ships a log viewer that treats evals as first-class artifacts.

The reference answer has four deliverables:

1. A **task module** — a single `@task` function that returns an `eval` specification composed of (dataset, solver, scorer).
2. A **solver pipeline** — a composition of built-in solvers (prompt template, chain of thought, generate) and at least one custom step that demonstrates the learner can write their own.
3. A **scorer** — a match-style or model-graded scorer with a committed grading contract and a bootstrap CI aggregator.
4. A **run manifest + log** — the exact `inspect eval` command, a pinned package version, a seed, and the committed `.eval` log file that Inspect View can replay.

This maps to the NIST AI RMF `MEASURE` function, which requires measurement to be "repeatable, with documented prompts and tools" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML09 Output Integrity Attacks** — Inspect's log file is the audit artifact that catches a solver silently rewriting outputs or a scorer silently passing a failing item; without the log, output-integrity drift is invisible ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Verify Attack` and `Erode ML Model Integrity` are the attacker techniques that Inspect's structured log is designed to leave fingerprints on ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Implementation

### 2.1 Directory layout

```
inspect_eval/
  README.md                         # task description, license, provenance
  pyproject.toml                    # pin inspect_ai and any extras
  tasks/
    __init__.py
    arithmetic_reasoning.py         # the @task function + solver + scorer
  data/
    dev.jsonl                       # ~20 items committed for smoke tests
    test.jsonl                      # a few hundred items committed
    checksums.sha256
  runs/
    2026-11-13/
      run.yaml                      # exact CLI + model + seed + hardware
      results.eval                  # Inspect log; openable with `inspect view`
      REPORT.md                     # summary + CI + gap table if needed
```

### 2.2 Dataset shape

One JSONL row per item. The schema below is the Inspect-friendly superset of what the task function needs:

```json
{
  "id": "ar-00007",
  "input": "A train leaves station A at 09:00 traveling 60 km/h. A second train leaves station B at 09:30 traveling 80 km/h toward A. Stations A and B are 300 km apart. At what time do they meet?",
  "target": "10:30",
  "metadata": {
    "difficulty": "medium",
    "topic": "rate-time-distance",
    "source": "<dataset-source>",
    "license": "CC-BY-4.0"
  }
}
```

The `input` / `target` names match Inspect's `Sample` schema, which lets the dataset loader hand rows to the solver with no extra plumbing.

### 2.3 Task module

`tasks/arithmetic_reasoning.py`:

```python
from inspect_ai import task, Task
from inspect_ai.dataset import json_dataset, Sample
from inspect_ai.solver import (
    chain,
    prompt_template,
    generate,
    solver,
    TaskState,
    Generate,
)
from inspect_ai.scorer import (
    scorer,
    Score,
    Target,
    accuracy,
    bootstrap_std,
    match,
    mean,
)


PROMPT = r"""Solve the following problem. Show your reasoning step by step, then
on a final line write exactly `Final answer: <answer>` where `<answer>` is the
shortest correct form.

Problem:
{prompt}
"""


@solver
def strip_scratchpad():
    """Remove hidden-scratchpad markers that some models emit before the Final answer line.

    This is a worked example of a custom Solver step. The scorer expects a specific
    final-answer format; a solver that normalizes the format keeps the scorer simple.
    """
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        text = state.output.completion
        # Drop any `<scratchpad>...</scratchpad>` block and collapse runs of blank lines.
        lower = text.lower()
        start = lower.find("<scratchpad>")
        end = lower.find("</scratchpad>")
        if start != -1 and end != -1 and end > start:
            text = text[:start] + text[end + len("</scratchpad>"):]
        state.output.completion = "\n".join(
            line for line in text.splitlines() if line.strip() != ""
        )
        return state
    return solve


@scorer(metrics=[accuracy(), bootstrap_std(), mean()])
def final_answer_match():
    """Extract the string after 'Final answer:' and compare, case-insensitively.

    Keeping the extraction inside a custom scorer (rather than a regex inside the solver)
    means the raw completion survives in the Inspect log for human review.
    """
    async def score(state: TaskState, target: Target) -> Score:
        text = state.output.completion or ""
        # Case-insensitive search for the final-answer cue, keep the original casing in the capture.
        lower = text.lower()
        key = "final answer:"
        idx = lower.rfind(key)
        if idx == -1:
            return Score(value=0.0, answer=None, explanation="no 'Final answer:' cue")
        answer = text[idx + len(key):].strip().splitlines()[0].strip().rstrip(".")
        correct = answer.lower() == target.text.strip().lower()
        return Score(
            value=1.0 if correct else 0.0,
            answer=answer,
            explanation=("match" if correct else f"expected {target.text!r}, got {answer!r}"),
        )
    return score


@task
def arithmetic_reasoning():
    return Task(
        dataset=json_dataset("data/test.jsonl", sample_fields=Sample),
        solver=chain(
            prompt_template(PROMPT),
            generate(max_tokens=512, temperature=0.0),
            strip_scratchpad(),
        ),
        scorer=final_answer_match(),
    )
```

Three patterns worth learning:

- **Solvers compose.** `chain(prompt_template(...), generate(...), strip_scratchpad())` is the Inspect idiom for "prompt → generate → post-process." Each step gets a `TaskState` in and returns one out; custom steps use the `@solver` decorator and an async function.
- **Scorers own the metric aggregation.** The `metrics=[accuracy(), bootstrap_std(), mean()]` list tells Inspect which aggregations to compute over per-item scores. `bootstrap_std()` emits the standard error for a bootstrap CI without extra code.
- **Explanations are first-class.** `Score(..., explanation="...")` is what the log viewer shows next to each item. Writing an explanation is not optional — it is the audit trail that distinguishes a scorer from a silent classifier.

### 2.4 Run the eval

```bash
pip install --no-deps 'inspect-ai==<pinned-version>'

inspect eval tasks/arithmetic_reasoning.py@arithmetic_reasoning \
    --model <vendor>/<model-id> \
    --model-config revision=<commit-sha>,dtype=bfloat16 \
    --seed 1234 \
    --log-dir runs/2026-11-13/ \
    --limit 500 \
    --max-tokens 512 \
    --temperature 0.0
```

Flag-by-flag:

- `inspect eval <path>@<fn>` runs the task function named `<fn>` in file `<path>`.
- `--model <provider>/<model-id>` selects an Inspect model provider (HuggingFace, OpenAI, Anthropic, Google, …). Pin the provider's model identifier here and the revision in `--model-config` where supported.
- `--seed 1234` fixes Inspect's sampling RNG; combined with `temperature=0.0` the eval is deterministic.
- `--log-dir` writes a `.eval` log file that `inspect view` opens. The log is the artifact; commit it.
- `--limit 500` keeps smoke runs cheap; drop the flag for a full pass.

### 2.5 Run manifest

`runs/2026-11-13/run.yaml`:

```yaml
inspect_version: "<version>"
task: "tasks/arithmetic_reasoning.py@arithmetic_reasoning"
model: "<vendor>/<model-id>"
model_revision: "<commit-sha>"
dtype: "bfloat16"
seed: 1234
max_tokens: 512
temperature: 0.0
dataset:
  path: "data/test.jsonl"
  checksum: "<sha256>"
  item_count: 500
hardware:
  gpus: "1x A100-80G"
  cuda: "12.4"
tolerance_window:
  absolute: 0.02           # ±2 pp vs the prior blessed run on this task
  rationale: "Matches the width of the bootstrap CI on a 500-item split."
```

### 2.6 Report shape

`runs/2026-11-13/REPORT.md`:

```
# Inspect eval — arithmetic_reasoning — 2026-11-13

## 1. Summary
accuracy = 0.742 ± 0.020 (95% bootstrap CI, 10000 resamples)
mean per-item score = 0.742
items scored = 500 / 500

## 2. Verdict
"Blessed run." OR
"Regression vs. 2026-10-30 (Δ = −0.031, tolerance = ±0.020). See §4."

## 3. Attachments
- run.yaml
- results.eval   (open with `inspect view --log-dir .`)

## 4. Regression root-cause table (if verdict is a regression)
<one row per suspect — see exercise-02 §2.5 for the pattern>
```

The `.eval` log committed alongside the report is the key artifact. Anyone with Inspect installed can run `inspect view --log-dir runs/2026-11-13/` and see every item's prompt, completion, score, and explanation without rerunning the model.

## 3. Validation steps

1. **Dry-run on dev.** `inspect eval ... --limit 20` on `data/dev.jsonl` must complete and produce a non-empty `.eval` log before the full run spends compute.
2. **Log-viewer round-trip.** Open `inspect view --log-dir runs/<date>/`; confirm each item shows the prompt, completion, and scorer explanation. If explanations are blank, the scorer is dropping context the human reviewer needs.
3. **Determinism check.** Re-run with the same seed, same model revision, same dataset checksum; `accuracy` must match to the last reported digit.
4. **Zero-cue audit.** Count items whose scorer explanation is `"no 'Final answer:' cue"`. If this is > 2–3% of the set, either raise `max_tokens`, tighten the prompt template, or add a repair step — don't let a quiet 5% silently count as failures.
5. **Scorer parity with eyeball judgment.** Sample 20 items at random; for each, compare the scorer's binary verdict to a human read of the completion. Disagreement rate should be ≤ 5% on arithmetic-style tasks; higher means the scorer is too strict (e.g., punishing "10:30 AM" when target is "10:30") or too loose (e.g., matching on substring).
6. **Checksum check.** `sha256sum -c data/checksums.sha256` passes before the `inspect eval` command runs.
7. **CI sanity.** The bootstrap CI (via `bootstrap_std` or an explicit bootstrap over the per-item scores) must bracket the accuracy point estimate. If it does not, the aggregator is misconfigured.

## 4. Rubric

Scored out of 10. The rubric rewards the eval being a **replayable audit artifact**, not merely a number.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Task is a committed `@task` function | 1 | `tasks/arithmetic_reasoning.py` exports an `arithmetic_reasoning` function decorated with `@task`. |
| R2 | Solver pipeline uses `chain(...)` with at least one custom step | 2 | The learner's own `@solver` function appears in the chain; its purpose is explained in a one-line docstring. |
| R3 | Scorer emits `Score(value, answer, explanation)` per item | 2 | Every log entry has a non-empty `explanation`; `inspect view` renders it. |
| R4 | Metrics include accuracy + bootstrap_std (or equivalent CI) | 1 | Scorer `metrics=[...]` includes both; the report's CI is derived from the log, not hand-written. |
| R5 | `.eval` log file is committed alongside the run manifest | 1 | `runs/<date>/results.eval` + `run.yaml` are in the repo. |
| R6 | Run manifest pins inspect version, model revision, dtype, seed | 1 | `run.yaml` has all five fields; `pip show inspect-ai` matches. |
| R7 | Dataset checksums verified before run | 1 | `make eval` (or an equivalent script) runs `sha256sum -c` before `inspect eval`. |
| R8 | Report has a one-sentence verdict | 1 | §2 of REPORT.md is a single sentence a reviewer can paste into chat. |

**Passing bar:** 7 / 10. Below that, the eval is a prototype; it is not a benchmark artifact.

### Review checklist (for a maintainer)

- [ ] `inspect view --log-dir runs/<date>/` opens and renders every item.
- [ ] No item shows a blank completion without the scorer flagging it.
- [ ] Custom solver docstring explains *why* the step exists.
- [ ] Scorer explanations are human-readable (not just `"ok"` / `"no"`).
- [ ] The bootstrap CI is computed from the per-item scores in the log, not pasted from a prior run.
- [ ] Regressions name a dominant suspect, not a paragraph of hedges.

## 5. Common mistakes

- **No `explanation` field on `Score`.** Inspect's audit value comes from the log viewer showing *why* each item scored the way it did. A boolean-only scorer throws away the main advantage of the framework.
- **Regex extraction inside the solver.** Doing the extraction in the solver (and mutating `state.output.completion`) hides the raw model text from the log. Keep extraction in the scorer; keep the raw text available for review.
- **Sampling enabled.** `temperature > 0` or `top_p < 1` makes the run irreproducible. For a benchmark pass, pin to greedy; use sampling only in sensitivity studies (see exercise-05).
- **Ad-hoc metric aggregation.** Writing `accuracy = hits / total` in the report instead of using the scorer's `metrics=[accuracy()]` means the CI and the aggregate can drift from the log's per-item scores.
- **Committing results without the `.eval` log.** The log is the artifact; a results summary without the log is unverifiable.
- **Not pinning the Inspect version.** Solver / scorer APIs evolve; a notebook that worked last month may silently change behavior on an upgrade.
- **Scoring on substring match.** `"10:30" in text` passes for `"The answer is not 10:30"`. Anchor the match to the Final-answer cue and compare the extracted token, not the whole completion.
- **Dropping items on scorer failure.** If the scorer raises on an unexpected completion shape, the item is excluded from the aggregate and the number silently drifts. Return `Score(value=0.0, explanation=...)` on malformed completions instead.
- **Reusing a log directory across runs.** Inspect appends to a log directory; two runs in the same directory make it impossible to reproduce "the number" from one of them. One directory per run, dated.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires measurement to be repeatable and documented; the Inspect `.eval` log is the measurement artifact that satisfies that requirement for an LLM eval.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** motivates keeping the raw completion in the log and scoring from it, rather than mutating completions in the solver.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Verify Attack` and `Erode ML Model Integrity` describe the attacker's interest in silently changing model outputs; a committed Inspect log is the defender's audit trail.

<!-- Local exercise context: the arithmetic_reasoning task name, PROMPT template, and the specific accuracy number (0.742) are illustrative. Real Inspect evals should substitute the learner's chosen dataset and the measured accuracy on the pinned model. -->
