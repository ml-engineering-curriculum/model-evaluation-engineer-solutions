# exercise-02 — Reproduce a Public HELM or lm-eval-harness Result — Solution

## 1. Solution overview

The exercise asks the learner to take a **public, published benchmark number** — a leaderboard row from HELM or a widely-cited `lm-evaluation-harness` number — and reproduce it inside their own environment, within a documented tolerance. The deliverable is not the number by itself; it is the **reproducibility report** that answers two questions:

1. Did the number reproduce? (point estimate + CI + tolerance window)
2. If it did not reproduce, *which pinnable thing* explains the gap?

The reference answer has four deliverables:

1. A **target claim** — exactly which benchmark, which model, which scenario / subtask, from which run of which harness, on which date. A reproduction of "MMLU on Llama" is not a reproduction; "MMLU `hendrycks_test` on `<org>/<model>@<commit>` as reported by HELM run `<run-name>` on `<date>`" is.
2. A **matched configuration** — the harness commit, the task version, the model weights revision, the prompting and few-shot configuration, the decoding parameters, and the metric aggregation; every item pinned.
3. A **reproduction run** that produces a result file and a CI, compared against the target with an *a priori* tolerance.
4. A **gap-analysis table** — if the reproduction does not match, which pinnable thing drifted (harness version, prompt template, tokenizer, hardware precision, random seed, dataset snapshot). The table is organized so each row is independently falsifiable.

This maps to the NIST AI RMF `MEASURE` and `MANAGE` functions, which direct teams to maintain **repeatability and reproducibility** evidence for measurement tools and to document deviations ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is MITRE ATLAS `Discover ML Model Family` and `Verify Attack` — attackers and defenders both need to know *which* version of *which* benchmark is being measured; a benchmark that drifts silently between runs is a surface both for inflated performance claims and for undetected regressions ([MITRE ATLAS](https://atlas.mitre.org/)). OWASP ML Top 10 **ML06 Corrupted Packages** is the most relevant OWASP control: a harness installed from an unpinned branch is a corrupted-package risk, not a convenience tradeoff ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)).

## 2. Implementation

### 2.1 Pick a reproducible target

Not every public number is reproducible. Pick a target that satisfies all three:

- **Open weights.** The model must be downloadable at a specific commit / revision. Closed-API numbers are rarely strictly reproducible because the vendor can change the model under you between the reported date and your run. Closed-API numbers can be *compared*, not *reproduced*.
- **Open data.** The scenario must be built from a dataset whose split and version are addressable (`hendrycks_test` on HuggingFace, a HELM-shipped scenario version, etc.). "Proprietary eval" reproductions are special cases that this exercise does not cover.
- **Open harness.** The published run must list the harness repository and the exact version / commit / scenario-spec that produced the number. If it does not, your reproduction's gap analysis has no shared ground truth to anchor against.

Worked example used in this solution: `hellaswag` as reported by the lm-evaluation-harness project for an open-weights Llama-family model, using the harness's built-in `hellaswag` task in `multiple_choice` mode. Pick whichever target the course distribution points you at — the structure of the reproduction report is the same.

### 2.2 Pin everything that can change

The reproduction configuration is a **pin manifest**. Every row names a thing that can change silently if it is not written down.

```yaml
# reproduction/pins.yaml
target:
  claim: "hellaswag acc_norm = 0.804 on <model_id>"
  source_url: "<URL of leaderboard row / model card / paper table>"
  reported_on: "2026-11-01"
  reported_tolerance: "± 0.5 pp (bootstrap 95% CI on 10042 items)"

harness:
  repo: "https://github.com/EleutherAI/lm-evaluation-harness"
  commit: "<40-char sha>"
  task_name: "hellaswag"
  task_version: 1.0            # value from the harness's task YAML metadata.version
  include_path: null           # using the harness's built-in task

model:
  id: "<org>/<model>"
  revision: "<commit-sha of the HF repo>"
  dtype: "bfloat16"
  tokenizer_id: "<same as model.id unless split>"
  tokenizer_revision: "<same sha>"

decoding:
  output_type: "multiple_choice"   # log-likelihood, no sampling
  temperature: null                # not used in multiple_choice
  seed: 1234

prompt:
  num_fewshot: 0
  fewshot_source: null
  prompt_template_hash: "<sha256 of the rendered doc_to_text on item id 0>"

data:
  dataset_path: "hellaswag"
  dataset_revision: "<HF dataset commit-sha or snapshot date>"
  split: "validation"
  split_item_count: 10042

hardware:
  gpus: "1x A100-80G"
  cuda: "12.4"
  torch: "2.5.1"
  transformers: "4.46.3"
  flash_attn: "2.6.3"

bootstrap:
  n_resamples: 10000
  seed: 1234

tolerance_window:
  absolute: 0.005                  # ±0.5 pp — must be declared BEFORE running
  rationale: "Matches the CI reported by the target; wider is dishonest, narrower is overconfident."
```

Two non-obvious rules:

- The **tolerance window is declared before the run.** If you set the tolerance after seeing the result, the exercise degrades into "move the goalposts until it passes."
- The `prompt_template_hash` is a sha256 of the rendered prompt for a specific item. This catches the single most common silent cause of non-reproduction: a prompt template that *looks* the same but differs in whitespace, newlines, or a missing "Answer:" cue.

### 2.3 Run the reproduction

```bash
pip install --no-deps "git+https://github.com/EleutherAI/lm-evaluation-harness@<pinned-commit-sha>#egg=lm_eval"

lm_eval \
    --model hf \
    --model_args pretrained=<org>/<model>,revision=<commit-sha>,dtype=bfloat16 \
    --tasks hellaswag \
    --num_fewshot 0 \
    --batch_size 16 \
    --seed 1234 \
    --output_path reproduction/results/hellaswag.json \
    --log_samples
```

The three `--log_*` / `--output_path` flags are not optional in a reproduction: without per-sample outputs, there is no way to localize the gap.

### 2.4 Build the comparison table

The output of the reproduction is **not** "the number." It is a one-page markdown report whose first table is this:

```
| Metric       | Target  | Reproduction | Δ       | CI (repro, 95%)   | Within tolerance? |
|--------------|---------|--------------|---------|-------------------|-------------------|
| acc          | 0.586   | 0.584        | −0.002  | [0.575, 0.593]    | yes               |
| acc_norm     | 0.804   | 0.803        | −0.001  | [0.795, 0.811]    | yes               |
```

The CI is a bootstrap over the item-level scores in the `--log_samples` file, with the seed pinned in the manifest. If the target publication did not report a CI, a bootstrap CI on *your* run is still the right thing to show, and the report should say so explicitly.

### 2.5 Gap analysis table (when the number doesn't reproduce)

If `|Δ| > tolerance.absolute`, the next deliverable is a **gap-analysis table**, not a narrative paragraph. Each row names a single pinnable thing that could explain the gap, with an experiment that falsifies it.

| Suspect | Why it could cause the gap | Falsification experiment |
|---|---|---|
| Harness commit mismatch | The target used an older task YAML with a different `doc_to_choice` serializer. | Re-run on the target's harness commit; if Δ closes, this was it. |
| Prompt template drift | `doc_to_text` emits a trailing space on one commit and not the other, shifting log-lik. | Compute `prompt_template_hash` on item 0 under both configurations. |
| Dataset snapshot | The HF `hellaswag` repo was re-exported with a different row order; log-lik is order-independent but length-normalization isn't on edge cases. | Pin `dataset_revision` and re-run; diff item counts and item ids. |
| Tokenizer drift | New BPE merges or a different `add_special_tokens` default change per-item log-lik by 0.1–0.5 pp aggregate. | Load both tokenizers; hash their vocabularies; diff. |
| Dtype / hardware | `bfloat16` on A100 vs. `float16` on V100 moves log-lik at the 4th decimal in aggregate, enough to matter near the tolerance. | Re-run in `float32` once; compare to `bfloat16`. |
| Batch size | Some backends change padding behavior with batch size, which shifts the log-lik of padded tokens. | Re-run with `--batch_size 1`; compare. |
| Fewshot drift | The target used `num_fewshot=10` from a specific demos file; you used `0`. | Match the fewshot setting exactly. |
| Metric aggregation | `acc_norm` divides by a byte length in one revision and a token length in another. | Diff the harness's aggregator function between commits. |
| Decontamination | A different decon filter dropped items from the eval. | Confirm item count matches the target. |

Rule: **one suspect per row, one experiment per suspect.** A narrative paragraph that mentions four suspects at once is not a gap analysis; it is a hedge.

### 2.6 Report shape

`reproduction/REPORT.md`:

```
# Reproduction report — hellaswag on <model_id>

## 1. Claim
<verbatim quote of the target claim, with URL and reported_on date>

## 2. Pins
<link to pins.yaml and highlight the ones that differ from "whatever pip installs today">

## 3. Numbers
<the comparison table from 2.4>
<the bootstrap CI configuration>

## 4. Verdict
"Reproduced within tolerance." OR
"Did not reproduce; Δ = <X>, tolerance = <Y>. Dominant suspect: <row from §5>."

## 5. Gap analysis (only if Δ > tolerance)
<the table from 2.5, with the experiment columns filled in>

## 6. Attachments
- pins.yaml
- results/hellaswag.json  (full harness output)
- samples/hellaswag_samples.jsonl  (per-item --log_samples)
- bootstrap_ci.json  (bootstrap config + per-run CI)
```

The verdict line is the first thing a reviewer reads and the first thing a leaderboard-watcher cites. Write it as a sentence the reader can paste into a slack message.

## 3. Validation steps

1. **Check the pin manifest against the environment.** Run `pip freeze | grep -E '^(lm_eval|torch|transformers|flash-attn)='` and confirm each line matches `pins.yaml`. If anything drifts, update the manifest *before* running the eval.
2. **Hash the prompt template on item 0.** Compute `sha256(doc_to_text(item[0]))` and record it in the manifest. A mismatch between this hash on your run and a target-run hash (when available) is a 60-second explanation for a 1-point gap.
3. **Item-count check.** The per-sample output file must contain exactly `split_item_count` rows. If it has fewer, a decontamination filter or a parse failure silently dropped items.
4. **Determinism dry-run.** Re-run the eval twice; metric cells must match to the last reported digit. Non-determinism at this stage is a bug, not a result.
5. **Point estimate vs. CI sanity.** The point estimate must be inside the reported CI. If it isn't, the CI configuration is wrong (wrong resamples, wrong seed, or bootstrap over the wrong field).
6. **Target-tolerance cross-check.** Compute `|Δ|` and compare to `tolerance.absolute`. If the tolerance is violated, do not update the tolerance; file the gap-analysis table.
7. **Signed report.** The REPORT.md header must name the engineer, the date, and the commit of this solution repo. "Reproduced within tolerance" without an owner is a non-statement.

## 4. Rubric

Scored out of 10. The rubric rewards the reproduction being **auditable**, not the number matching.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Target claim is cited with URL, date, and exact scenario | 1 | `pins.yaml :: target` has all four fields; the claim is a verbatim quote. |
| R2 | Pin manifest covers harness, model, dataset, hardware | 2 | Every field in §2.2 is non-null; `commit-sha` values are 40-char hex. |
| R3 | Tolerance is declared before the run | 1 | `tolerance_window` is committed in the same PR as `pins.yaml`, before `results/`. |
| R4 | Numbers table shows target, reproduction, Δ, and CI | 2 | §2.4 table is in `REPORT.md` with bootstrap CI pinned. |
| R5 | Prompt-template hash is committed | 1 | `prompt_template_hash` in `pins.yaml` matches a hash computed from the `--log_samples` file. |
| R6 | Verdict sentence is explicit | 1 | §4 of the report contains either "Reproduced within tolerance" or a named dominant suspect — no hedging paragraph. |
| R7 | Gap analysis is a falsifiable table when Δ > tolerance | 1 | Each row has a single suspect + a single experiment; narratives are not accepted. |
| R8 | Item count matches the published split | 1 | Per-sample file row count equals `split_item_count`; decontamination drops are logged. |

**Passing bar:** 7 / 10. Below that, the reproduction is anecdotal, not evidentiary.

### Review checklist (for a maintainer)

- [ ] `pip freeze` matches `pins.yaml`.
- [ ] Per-sample output file row count equals `split_item_count`.
- [ ] CI is computed on your run, not copied from the target's reported CI.
- [ ] Verdict sentence names either "reproduced" or a single dominant suspect.
- [ ] When Δ > tolerance, every row of the gap table has a falsification experiment, not just a hypothesis.
- [ ] The report has an engineer, a date, and a solution-repo commit sha in its header.

## 5. Common mistakes

- **Reproducing "MMLU" without naming the subtask / split.** MMLU subset selection, 0-shot vs 5-shot, and the specific prompt template each move the number by several points. "Reproduce MMLU" is underspecified by default.
- **Comparing against a vendor closed-API number as if it were a reproduction target.** Closed-API endpoints can change under you between the target's run and yours. Call this a *comparison*, not a reproduction.
- **Picking the tolerance after the run.** This turns the exercise into a goal-seek exercise and defeats the point. Commit the tolerance before `results/` exists.
- **Reporting the target's CI instead of your own.** Borrowed CIs are not CIs; they are decoration. Compute a bootstrap on your `--log_samples` file.
- **Omitting `--log_samples`.** Without per-sample outputs, there is no way to localize the gap, and the gap analysis degenerates into speculation.
- **Narrative gap analysis.** "Maybe the tokenizer, or maybe the seed" is not an analysis. One row per suspect, one experiment per suspect.
- **Running on different hardware without recording it.** `bfloat16` on A100 and `float16` on V100 do not produce the same log-likelihoods. Hardware is a pin.
- **Silent item drops.** A split with 10,042 items that produces 10,039 scored items is a bug; always reconcile the item count to the published split.
- **Treating "within tolerance" as proof the model matches the target run.** It is evidence, not proof. Two different models can produce the same aggregate within a half-point by coincidence; always keep item-level outputs so a later disagreement is diagnosable.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires repeatability / reproducibility evidence for measurement tools, and `MANAGE` requires documented deviations when a measurement is not reproduced.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML06 Corrupted Packages** motivates pinning the harness commit and the model revision; **ML02 Data Poisoning** motivates pinning the dataset revision and counting items.
- MITRE ATLAS — <https://atlas.mitre.org/>. The `Discover ML Model Family` and `Verify Attack` techniques describe adversaries probing which exact version of a model / benchmark is in use; a reproduction report is the defender's answer to the same question.

<!-- Local exercise context: the hellaswag point estimates (0.584 / 0.803), the pinned hardware, and the specific suspect rows are illustrative worked values. The real reproduction must substitute the engineer's chosen target claim and whatever the harness and model actually produce on the measured hardware. -->
