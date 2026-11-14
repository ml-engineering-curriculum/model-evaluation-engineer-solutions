# exercise-01 — Register a Custom Task in lm-evaluation-harness — Solution

## 1. Solution overview

The exercise asks the learner to extend EleutherAI's `lm-evaluation-harness` with a **custom task** that exercises both scoring styles the harness supports natively:

- **Log-likelihood (multiple-choice) scoring** — the model's conditional log-probability of each candidate completion is compared; the argmax defines the prediction.
- **Generation scoring** — the model generates free-form text that is compared against gold references by one or more exact / regex / normalized metrics.

A "custom task" in the harness is a declarative YAML file plus (optionally) a small Python module for preprocessing / postprocessing and non-trivial metrics. The task is then registered in the harness's task registry so that `lm_eval --tasks <task_name>` picks it up.

The reference answer has five deliverables:

1. A **task YAML pair** — one YAML for the log-likelihood variant, one YAML for the generation variant, sharing a common dataset and prompt core so results are comparable.
2. A **preprocessing / metrics module** — a committed Python file implementing `doc_to_text`, `doc_to_target`, and any non-standard metric aggregation.
3. A **registry hookup** — a `tasks/` subpackage that the harness picks up either via `--include_path` or (for an in-repo installation) via the existing registry mechanism.
4. A **reproduction manifest** — exact harness version, exact model id, exact random seed, and the exact `lm_eval` command; a result row that another engineer can reproduce bit-identically on the same hardware.
5. A **gate / review checklist** that treats the custom task as a *controlled benchmark artifact*, not a one-off script.

This maps to the NIST AI RMF `MEASURE` function, which calls for metrics to be "tested, documented, and tied to an identified operational context" rather than ad-hoc ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is **MITRE ATLAS** `Discover ML Model Family` and the broader ML supply-chain techniques — a custom eval that is not versioned, seeded, and license-traced is exactly the kind of benchmark artifact that lets corrupted-package / corrupted-benchmark risk hide ([MITRE ATLAS](https://atlas.mitre.org/)). OWASP ML Top 10 **ML06 Corrupted Packages** and **ML02 Data Poisoning** are the most relevant OWASP controls: a custom task that pulls data from an unpinned source or lacks a checksum is a poisoning surface ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)).

## 2. Implementation

### 2.1 Directory layout

Put the custom task in its own directory outside the harness install so you can version it independently, then point the harness at it with `--include_path`.

```
custom_tasks/
  trivia_facts/
    README.md                     # task description, license, provenance
    trivia_facts_loglik.yaml      # log-likelihood multiple-choice variant
    trivia_facts_gen.yaml         # generation variant
    utils.py                      # doc_to_text / doc_to_target / normalizers
    data/
      dev.jsonl                   # 50-item dev split (committed)
      test.jsonl                  # 500-item test split (committed; small, fixed)
      checksums.sha256            # per-file checksums
    reproduction.md               # manifest: harness commit, model id, seed, exact CLI
```

Rule: **data files are committed** (or pinned to a dataset version with a hash). An eval whose data can silently change between runs is not a benchmark, it is a weather report.

### 2.2 Dataset shape

For both variants, each dev / test row is a single JSON object:

```json
{
  "id": "tf-00042",
  "question": "Which element has the chemical symbol 'Au'?",
  "choices": ["Silver", "Gold", "Copper", "Lead"],
  "answer_index": 1,
  "answer_text": "Gold",
  "source": "wikipedia-chemical-elements-2023-10",
  "license": "CC-BY-SA-3.0"
}
```

The log-likelihood variant will use `choices` + `answer_index`. The generation variant will use `question` + `answer_text` and score with a normalized string match. Sharing the same rows across variants lets the learner compare "what the model knows" (log-lik) versus "what the model says" (generation) on an *item-identical* set — the single most useful diagnostic the harness supports.

### 2.3 Log-likelihood variant YAML

`trivia_facts_loglik.yaml`:

```yaml
task: trivia_facts_loglik
dataset_path: json
dataset_kwargs:
  data_files:
    test: data/test.jsonl
    validation: data/dev.jsonl
test_split: test
validation_split: validation

output_type: multiple_choice           # harness built-in: log-likelihood over candidate completions
doc_to_text: "Question: {{question}}\nAnswer:"
doc_to_choice: "{{choices}}"
doc_to_target: "{{answer_index}}"      # integer index into doc_to_choice

should_decontaminate: true
doc_to_decontamination_query: "{{question}}"

metric_list:
  - metric: acc
    aggregation: mean
    higher_is_better: true
  - metric: acc_norm                   # length-normalized log-likelihood (harness built-in)
    aggregation: mean
    higher_is_better: true

num_fewshot: 0

metadata:
  version: 1.0
  license: "CC-BY-SA-3.0"
  provenance_path: "data/checksums.sha256"
```

Notes:

- `output_type: multiple_choice` is the harness's built-in log-likelihood scoring mode. The harness computes `logP(choice | prompt)` for every entry in `doc_to_choice`, and `acc` is 1 when the argmax equals `doc_to_target`.
- `acc_norm` divides each log-likelihood by the choice's byte length. It is the harness's standard length-normalized variant; keep it in the metric list so learners can see how it changes the ranking on items where choices have very different lengths.
- `should_decontaminate: true` + `doc_to_decontamination_query` are the harness's n-gram overlap hook. This does **not** prove the model is clean; it reports overlap statistics that a reviewer uses as evidence. Contamination is treated at length in exercise-03 of mod-102.

### 2.4 Generation variant YAML

`trivia_facts_gen.yaml`:

```yaml
task: trivia_facts_gen
dataset_path: json
dataset_kwargs:
  data_files:
    test: data/test.jsonl
    validation: data/dev.jsonl
test_split: test
validation_split: validation

output_type: generate_until
doc_to_text: "Question: {{question}}\nAnswer:"
doc_to_target: "{{answer_text}}"

generation_kwargs:
  until:
    - "\n"
    - "Question:"
  max_gen_toks: 32
  temperature: 0.0
  do_sample: false

filter_list:
  - name: "normalize-and-first-line"
    filter:
      - function: !function utils.normalize_answer
      - function: !function utils.take_first_line

metric_list:
  - metric: exact_match
    aggregation: mean
    higher_is_better: true
  - metric: !function utils.normalized_exact_match
    aggregation: mean
    higher_is_better: true

num_fewshot: 0

metadata:
  version: 1.0
  license: "CC-BY-SA-3.0"
  provenance_path: "data/checksums.sha256"
```

Notes:

- `output_type: generate_until` is the harness's free-generation mode. `until` is the stop-sequence list; `max_gen_toks` bounds runaway generations.
- `temperature: 0.0` + `do_sample: false` is the only defensible default for a benchmark pass — stochastic decoding at eval time makes "reproduce this number" a nondeterministic conversation.
- `filter_list` is the harness's post-processing chain. Filters run **before** metric computation; this is where you normalize whitespace, drop common prefixes like "The answer is …", and clip to the first line.
- `!function utils.foo` is the harness's reference syntax that points at a Python callable in the task module.

### 2.5 Utils module

`utils.py`:

```python
import re
import string


_ARTICLE_PATTERN = re.compile(r"\b(a|an|the)\b", flags=re.IGNORECASE)
_WS_PATTERN = re.compile(r"\s+")
_PUNC_TABLE = str.maketrans("", "", string.punctuation)


def normalize_answer(text: str) -> str:
    """SQuAD-style normalization: lowercase, strip articles, strip punct, collapse ws."""
    text = text.lower()
    text = _ARTICLE_PATTERN.sub(" ", text)
    text = text.translate(_PUNC_TABLE)
    text = _WS_PATTERN.sub(" ", text).strip()
    return text


def take_first_line(text: str) -> str:
    """Generation can continue past the answer; take the first non-empty line."""
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def normalized_exact_match(predictions, references):
    """Harness metric callback signature: lists of strings in, float out.

    We normalize both sides with the same function so that casing, articles,
    and trailing punctuation do not drive the score. The non-normalized
    exact_match is kept in the metric list so a reviewer can see the gap.
    """
    hits = 0
    for pred, ref in zip(predictions, references):
        if normalize_answer(pred) == normalize_answer(ref):
            hits += 1
    return hits / max(len(predictions), 1)
```

Two patterns worth learning:

- The **same** normalization function is applied to both predictions and references. Normalizing only predictions is a classic benchmark bug and inflates scores by a few points for no good reason.
- The non-normalized `exact_match` stays in the metric list. The gap between `exact_match` and `normalized_exact_match` is itself a signal: if it is huge, the model is probably right most of the time but your prompt is leaking "The answer is …" preambles that your filter didn't catch.

### 2.6 Registry hookup

Two ways the harness picks up the task:

1. **`--include_path` (recommended for learner-grade custom tasks).** Keep `custom_tasks/trivia_facts/` outside the harness install and pass `--include_path custom_tasks/` to `lm_eval`. The harness walks that directory for YAML files and registers tasks by their `task:` key. This is the path that survives a harness upgrade cleanly.

2. **In-tree registration.** Drop the directory under `lm_eval/tasks/trivia_facts/` in a fork of the harness and open a PR upstream. Only do this if the task is genuinely public and you accept the maintenance burden.

The committed `README.md` next to the YAMLs must call out:

- The exact source of the data, with a URL and an `acquired_on` date.
- The license (`CC-BY-SA-3.0` in this worked example) and its downstream obligations (attribution, share-alike).
- The checksum file so a reviewer can detect drift between the committed data and what the task runs on.

### 2.7 Running it

Pin the harness commit, the model id, and the seed. These three numbers are the reproduction contract:

```bash
# Pin the harness.
pip install --no-deps \
    "git+https://github.com/EleutherAI/lm-evaluation-harness@<pinned-commit-sha>#egg=lm_eval"

# Log-likelihood variant.
lm_eval \
    --model hf \
    --model_args pretrained=<org>/<model>,revision=<commit-sha>,dtype=bfloat16 \
    --tasks trivia_facts_loglik \
    --include_path custom_tasks \
    --num_fewshot 0 \
    --batch_size 8 \
    --seed 1234 \
    --output_path results/trivia_facts_loglik.json \
    --log_samples

# Generation variant.
lm_eval \
    --model hf \
    --model_args pretrained=<org>/<model>,revision=<commit-sha>,dtype=bfloat16 \
    --tasks trivia_facts_gen \
    --include_path custom_tasks \
    --num_fewshot 0 \
    --batch_size 8 \
    --seed 1234 \
    --output_path results/trivia_facts_gen.json \
    --log_samples
```

Why each flag:

- `--model hf` selects the HuggingFace Transformers backend; `--model_args` pins `pretrained` + `revision` so the weights are not a moving target.
- `--num_fewshot 0` is explicit even though the YAML sets it — never let shells and YAMLs disagree; flags-win-over-YAML is the harness's convention.
- `--seed 1234` fixes the harness's RNG. Generation at `temperature=0` is deterministic given the seed; log-lik is deterministic by construction.
- `--log_samples` writes one JSON line per item (prompt, prediction, target, per-item metric). This is the only way a reviewer can later audit a single wrong answer without rerunning the eval.

### 2.8 Reproduction manifest

`reproduction.md` is the single file a second engineer reads to reproduce the number:

```
Task:                 trivia_facts_loglik + trivia_facts_gen
Harness commit:       <sha from `pip show lm_eval`>
Model id:             <org>/<model>
Model revision:       <commit-sha>
Dtype:                bfloat16
Device:               1x A100-80G
Batch size:           8
Seed:                 1234
num_fewshot:          0
Data checksums:       data/checksums.sha256
Headline numbers:     acc=0.741 ± 0.019 (loglik), em=0.682 ± 0.021 (gen)
Confidence interval:  95% bootstrap over test set, 10000 resamples, seed 1234
```

Headline numbers are illustrative — the real numbers come from running the harness. The **bootstrap seed is pinned** so the CI is reproducible, not just the point estimate.

## 3. Validation steps

1. **Dry-run on the dev split.** `lm_eval --tasks trivia_facts_loglik --limit 10 --tasks ...` must complete end-to-end before you spend compute on the test split. If it fails here, the YAML / module is wrong; the model is not the suspect.
2. **Round-trip the YAML.** Open the result file produced with `--log_samples` and confirm that `doc_to_text` rendered the prompt you expected, and that `doc_to_choice` emitted the right candidate list. A YAML typo here silently grades a different prompt.
3. **Determinism check.** Run both variants twice, same seed, same hardware. All metric cells must match to the last reported digit. If they drift, something upstream is non-deterministic (a tokenizer switch, a dropout path, a `do_sample=True` left over from debugging).
4. **Log-lik vs generation agreement sanity check.** On the shared item set, compute `item-level agreement = fraction of items where loglik prediction == generation prediction (after normalization)`. A large disagreement (>20 points) is a red flag: either the generation filter is dropping real answers, or the log-lik candidate set doesn't cover what the model wants to say.
5. **Decontamination report.** If `should_decontaminate: true` is set, inspect the harness's overlap statistics. A high overlap with any known pretraining corpus is not automatically disqualifying, but it is a disclosure obligation on the result card.
6. **Checksum check.** `sha256sum -c data/checksums.sha256` must pass before the `lm_eval` command runs. Wire this into a `make eval` target so it is not a human step.
7. **License surfacing.** The harness `--output_path` JSON records task metadata. Confirm `license` and `version` from the YAML show up in the result file — if they do not, result cards will quietly drop the provenance.

## 4. Rubric

Scored out of 10. The rubric rewards the task being a **reproducible controlled artifact**, not merely a working script.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Task is defined by committed YAML, not ad-hoc code | 2 | `trivia_facts_loglik.yaml` and `trivia_facts_gen.yaml` both load via the harness's YAML registry without edits to the harness source. |
| R2 | Both scoring styles cover the same item set | 1 | Dev / test JSONL rows are shared; log-lik uses `choices`+`answer_index`, generation uses `answer_text`. |
| R3 | Prompt template is explicit and templated | 1 | `doc_to_text` uses `{{question}}` placeholders; no string concat in Python that bypasses the YAML. |
| R4 | Generation variant is greedy and stop-sequenced | 1 | `temperature=0.0`, `do_sample=false`, `until:` includes at least the newline and the next question marker. |
| R5 | Filters are applied to both predictions and references | 1 | `normalize_answer` is called on both sides in `normalized_exact_match`; non-normalized `exact_match` is kept in the metric list for comparison. |
| R6 | Reproduction manifest pins harness commit, model revision, dtype, seed | 2 | `reproduction.md` has all five fields; `pip show lm_eval` matches the pinned commit. |
| R7 | Data provenance is committed | 1 | `data/checksums.sha256` exists, is verified in CI, and is referenced from both YAMLs' `metadata.provenance_path`. |
| R8 | Decontamination and license metadata are surfaced in the result file | 1 | `--log_samples` output contains `license`, `version`, and (if enabled) the overlap report. |

**Passing bar:** 7 / 10. Below that, the task is a prototype rather than a benchmark.

### Review checklist (for a maintainer)

- [ ] `--include_path` resolves the task without editing the harness install.
- [ ] Same data rows power both variants (join by `id`).
- [ ] Stop sequences are tight enough that the model cannot run off the end of the answer into the next question.
- [ ] The normalization applied to predictions is **identical** to the normalization applied to references.
- [ ] A fresh clone + `make eval` produces byte-identical metric cells.
- [ ] The result file carries the license and version metadata; downstream result cards do not have to re-derive provenance.

## 5. Common mistakes

- **Normalizing only the prediction.** Lowercasing the model's output but not the reference inflates `exact_match` on items where the reference has a trailing period or an article. Normalize both sides with the same function.
- **Leaving sampling on for a benchmark pass.** `temperature > 0` or `do_sample=true` makes the number irreproducible. Save sampling for sensitivity analysis (see exercise-05), not for the headline score.
- **No stop sequences.** Without `until:`, the generation runs until `max_gen_toks`, and the filter has to cut the answer out of a paragraph. That is a recipe for silent scoring errors on long-tail items.
- **`doc_to_text` built in Python instead of the YAML.** The YAML is the artifact a reviewer reads. If the real prompt is assembled in a Python preprocess step that is not surfaced in the YAML, reviewers approve a prompt that is not what runs.
- **Unpinned harness.** `pip install lm_eval` on two machines a week apart does not install the same code. Pin the commit.
- **Unpinned model weights.** `pretrained=<org>/<model>` without `revision=<sha>` means the weights can change under you. Pin the revision.
- **Committing a huge test split.** Keep committed splits small (hundreds of items); pin a dataset version + checksum for anything larger. A 10GB committed test file turns the solution repo into a storage system.
- **Skipping decontamination.** Omitting `should_decontaminate` is not a bug, but it is an unstated assumption. State it either way in the README so reviewers do not have to guess.
- **Different random seed in the two YAMLs.** The CLI `--seed` is authoritative, but divergent default seeds inside helper code undermine the "log-lik and generation share the same items" story.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires metrics that are tested, documented, and tied to an operational context; a custom harness task is the operationalization of that for an LLM benchmark.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML02 Data Poisoning** and **ML06 Corrupted Packages** motivate the checksum + pinned-harness + pinned-data requirements in this solution.
- MITRE ATLAS — <https://atlas.mitre.org/>. The `Discover ML Model Family` and supply-chain techniques motivate treating a custom task as a controlled artifact whose version, license, and data are explicitly tracked.

<!-- Local exercise context: the trivia_facts item schema, the TF-00042 example, and the specific numbers in the reproduction manifest are illustrative only. Real custom tasks must use data the organization is actually licensed to publish, with checksums over the actual files. -->
