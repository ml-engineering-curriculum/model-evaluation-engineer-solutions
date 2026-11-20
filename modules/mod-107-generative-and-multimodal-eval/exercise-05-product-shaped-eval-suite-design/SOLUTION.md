# exercise-05 — Product-Shaped Eval Suite Design — Solution

## 1. Solution overview

The first four exercises in mod-107 each produce a *component* measurement — a code eval (pass@k), a math eval (robust extraction + symbolic equivalence), a RAG eval (component triad), a multimodal eval (three-metric headline). This exercise is a **design** exercise: the learner wires those components into a single **product-shaped eval suite** whose purpose is to answer one question the business actually cares about — *"is the next release of this product safer, more useful, and more honest than the current one?"*

A product-shaped suite differs from a research-shaped suite in four specific ways:

1. The **scope is defined by a product spec**, not by the capabilities the model happens to have. A math eval exists only if the product solves math; a VQA eval exists only if the product takes images.
2. The **population is drawn from the product's traffic**, not from a public benchmark alone. Public benchmarks guard against regression on a known distribution; the product traffic slice is the one that actually ships.
3. **Gates are ship / no-ship**, not relative rankings. Each component has a committed threshold, and a failing component blocks the release until it is resolved — not averaged into a vibe score.
4. **The suite is versioned as one artifact.** A result row cites the suite version, the dataset slice version, the judge versions, and the model under test; a later reviewer can rerun the exact suite that gated an earlier release.

The reference answer has four deliverables:

1. A **product spec summary + capability matrix** — a short document that names the product, its user-facing capabilities, and the component evals that apply, with evals explicitly marked `not-applicable` where the product does not exercise them.
2. A **suite manifest** — a single committed YAML that pins every component eval (dataset SHAs, prompt SHAs, judge model, sandbox digest, seed) and declares per-component ship/no-ship gates.
3. A **worked suite instance** — a concrete `suite.v1.yaml` and a filled-in `readout.md` for a hypothetical product, showing a per-component verdict and a final ship decision.
4. A **grading rubric** that grades the design on the discipline of its gates (committed thresholds, no silent soft-passes, named owners), not on how high the numbers are.

This maps directly to the NIST AI RMF `MEASURE` function, which asks for metrics tied to operational context and tested against identified risks, and `MANAGE`, which asks that the risk management decisions be documented and tied to a named decision maker ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 as a whole: a product eval that omits a capability-matrix row for a capability the model has is leaving a surface undefined, and every ML-Top-10 risk hides more easily on undefined surfaces ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS gives the attacker view: an attacker reading the suite manifest would find the untested capability and attack there first ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

The worked example is a hypothetical "research assistant" product: given a user question, optionally with uploaded documents and / or an image, it returns an answer that may include code snippets and arithmetic. The capability matrix identifies four surfaces (code, math, RAG, vision) and marks each as `applicable` or `not-applicable`. For this product, all four are applicable.

### 2.1 Product spec summary

Commit `suite/product.md`:

```
# Product: Research Assistant (ra-v2)

Users: internal technical staff.

Supported inputs:
  - natural-language question (always)
  - 0..10 uploaded documents (optional; triggers RAG path)
  - 0..1 uploaded image (optional; triggers vision path)

Supported outputs:
  - prose answer
  - optional code block (python, go, rust) when the user asks for code
  - optional citation list when documents were provided

Risk tier: internal + non-regulated use. No user-facing medical / legal /
financial guidance. Refusal rate target: 0% on in-scope, 100% on
out-of-scope (names a committed out-of-scope list).

Primary quality concerns, in order:
  1. Faithfulness to provided documents when present.
  2. Correctness of code and arithmetic when present.
  3. Non-hallucination of image contents when image is present.
  4. Answer relevance to the stated question.
```

### 2.2 Capability matrix (`suite/capability_matrix.md`)

```
| Capability          | Applies? | Component eval                        | Why / why not                                       |
|---------------------|----------|---------------------------------------|-----------------------------------------------------|
| Code generation     | yes      | pass@k on mini_py_v1 (exercise-01)    | Product emits code blocks on request.               |
| Math reasoning      | yes      | strict + if-extracted on mini_math_v1 | Product performs arithmetic in answers.             |
| RAG                 | yes      | RAGAS+TruLens triad on mini_rag_v1    | Product takes uploaded documents.                   |
| Multimodal VQA      | yes      | VQA soft-acc on mini_vqa_v1           | Product takes a single uploaded image.              |
| Multimodal grounding| no       | mini_refcoco_v1 (n/a)                 | Product does not emit bounding boxes.               |
| Multimodal POPE     | yes      | POPE triad on mini_pope_v1            | Hallucination over uploaded images is a top risk.   |
| Human SxS pairwise  | yes      | 50 prompts, 2 raters/item             | Headline users-prefer-new rate; mod-106 protocol.   |
| Safety / red-team   | yes      | see mod-109 suite                     | Linked, not duplicated here.                        |
```

Rules:

- **"Not-applicable" is a decision, not an omission.** A row without a reason is treated as missing coverage. CI checks every row has a one-line justification.
- **Linked suites are listed, not inlined.** The mod-109 safety suite is the authoritative source for safety gates; the product suite references it so there is one place to update the rules.

### 2.3 Suite manifest (`suite/suite.v1.yaml`)

The manifest is the single artifact that gates a release. Every eval is pinned; every gate has a committed numeric threshold and a named decision authority.

```yaml
suite_version: v1.0.0
suite_commit: <git sha>
product:
  id: ra-v2
  spec_sha256: <sha of suite/product.md>
  capability_matrix_sha256: <sha of suite/capability_matrix.md>

model_under_test:
  id: claude-opus-4-7
  decoding:
    temperature: 0.0
    max_tokens: 2048
  system_prompt_sha256: <sha>

# Deterministic inputs
seed: 20261120

components:

  code_pass_at_k:
    exercise: exercise-01
    dataset:  problems/mini_py_v1.jsonl
    dataset_sha256: <hex>
    sandbox_image: ghcr.io/example/code-eval-python@sha256:<hex>
    n: 10
    k_list: [1, 5, 10]
    gates:
      - metric: pass@1
        threshold: ">= 0.45"
        rationale: "current prod is 0.42; a release at < 0.45 regresses."
      - metric: pass@5
        threshold: ">= 0.70"

  math_strict:
    exercise: exercise-02
    dataset:  problems/mini_math_v1.jsonl
    dataset_sha256: <hex>
    sympy_version: "1.12"
    gates:
      - metric: accuracy_strict
        threshold: ">= 0.65"
      - metric: dropped_frac
        threshold: "<= 0.10"
        rationale: "extractor failures above 10% mask the real model quality."

  rag_triad:
    exercise: exercise-03
    dataset:  data/mini_rag_v1.jsonl
    dataset_sha256: <hex>
    judge_model: claude-opus-4-7
    prompt_shas:
      faithfulness:      <hex>
      answer_relevancy:  <hex>
      context_precision: <hex>
      context_recall:    <hex>
    gates:
      - metric: ragas.faithfulness
        threshold: ">= 0.75"
      - metric: ragas.context_precision
        threshold: ">= 0.70"
      - metric: cross_judge.items_flagged_fraction
        threshold: "<= 0.20"
        rationale: "more than 20% judge disagreement makes the mean uninterpretable."

  multimodal_vqa:
    exercise: exercise-04
    dataset:  data/vqa/mini_vqa_v1.jsonl
    dataset_sha256: <hex>
    gates:
      - metric: mean_soft_acc
        threshold: ">= 0.60"
      - metric: by_category.counting
        threshold: ">= 0.40"
        rationale: "counting is the lowest sub-metric; a regression below 0.40 ships a visible bug."

  multimodal_pope:
    exercise: exercise-04
    dataset:  data/pope/mini_pope_v1.jsonl
    dataset_sha256: <hex>
    gates:
      - metric: accuracy
        threshold: ">= 0.75"
      - metric: yes_rate
        threshold: "abs(x - 0.5) <= 0.10"
        rationale: "a balanced POPE split should produce a yes-rate near 0.5; far from it is an agreement bias."

  human_sxs:
    exercise: mod-106/exercise-04      # linked to human-eval suite
    dataset:  human_sxs/ra_v2_pilot.jsonl
    raters:   2
    gates:
      - metric: win_rate_new_vs_current
        threshold: ">= 0.52"
      - metric: tie_rate
        threshold: "<= 0.40"
        rationale: "tie_rate above 0.40 means the human instrument is not separating the two systems; fix the task before relying on the number."

ship_decision:
  all_gates_must_pass: true
  tie_breaker: human_sxs
  decision_authority: "product lead + eval lead (named individuals)"
  on_fail:
    procedure: "file a 'gate-failed' issue per failing component; block release in CI until each is closed with a linked rerun that passes."
```

Design rules:

- **Every gate is numeric.** No "looks good", no "approximately." `>= 0.45`, `<= 0.10`, `abs(x - 0.5) <= 0.10`.
- **Every gate has a rationale when the threshold is non-obvious.** The reader six months later should not have to guess why `0.45` was the line.
- **`all_gates_must_pass: true`.** Averaging across gates is how a safety-critical gate gets outvoted by cheap wins. Each component is a veto.
- **Tie-breaker is named.** If the model passes every automated gate but ties on human SxS, the explicit tie-breaker policy prevents a late-stage argument over whose number counts.
- **Decision authority is a person.** `decision_authority` is a committed name, not "the team." A gate with no owner is a gate nobody will read a fail on.
- **`on_fail` is a procedure, not a hand-wave.** A failing gate opens an issue; the issue is closed by a linked rerun. The paper trail is automatic.

### 2.4 Worked readout (`suite/readout_2026-11-20.md`)

A readout is one page. Fixed sections so three readouts in a row are directly comparable.

```
# Suite readout — ra-v2 vs ra-v1 — 2026-11-20

suite_version: v1.0.0  (commit: <sha>)
model_under_test: claude-opus-4-7
run_id: ra-v2_opus-4-7_2026-11-20

## Gate table
| Component        | Metric                         | Threshold               | Observed  | Pass |
|------------------|--------------------------------|-------------------------|-----------|------|
| code_pass_at_k   | pass@1                         | >= 0.45                 | 0.48      | yes  |
| code_pass_at_k   | pass@5                         | >= 0.70                 | 0.73      | yes  |
| math_strict      | accuracy_strict                | >= 0.65                 | 0.68      | yes  |
| math_strict      | dropped_frac                   | <= 0.10                 | 0.06      | yes  |
| rag_triad        | ragas.faithfulness             | >= 0.75                 | 0.78      | yes  |
| rag_triad        | ragas.context_precision        | >= 0.70                 | 0.66      | no   |
| rag_triad        | cross_judge.items_flagged_frac | <= 0.20                 | 0.12      | yes  |
| multimodal_vqa   | mean_soft_acc                  | >= 0.60                 | 0.68      | yes  |
| multimodal_vqa   | by_category.counting           | >= 0.40                 | 0.44      | yes  |
| multimodal_pope  | accuracy                       | >= 0.75                 | 0.78      | yes  |
| multimodal_pope  | yes_rate (abs vs 0.5)          | <= 0.10                 | 0.09      | yes  |
| human_sxs        | win_rate_new_vs_current        | >= 0.52                 | 0.55      | yes  |
| human_sxs        | tie_rate                       | <= 0.40                 | 0.33      | yes  |

## Ship decision
no-ship. Blocked by: rag_triad.ragas.context_precision = 0.66 < 0.70.

## Follow-up
- Owner: @retrieval-team
- Action: investigate retriever change in commit <sha>; expected rerun 2026-11-24.
- Linked issue: #4211.

## Notes
- Every other gate passed; math and multimodal both regressed-safely well above their thresholds.
- `yes_rate` 0.59 is within the committed +/-0.1 band; no POPE regression suspected.
- Suite version v1.0.0 is unchanged from the ra-v1 run; metric deltas are attributable to the model/retriever change.
```

Design rules of the readout:

- **Single `yes` / `no` per gate.** A gate that fails even by a small margin is a `no`. The ship decision is the AND of every gate.
- **Ship decision has an owner and a date.** A no-ship with no named follow-up owner is a stall, not a ship-blocking failure.
- **Suite version is in the readout header.** When a later reader compares two readouts and the suite version differs, the comparison is immediately disqualified without hunting through notes.
- **"Notes" section acknowledges the regressions that passed.** A metric that dropped but stayed above its gate is still worth calling out; the next release's "did a passing gate secretly erode" review needs that context.

### 2.5 Run orchestration

A single CLI runs every component against the manifest and emits the readout.

```
$ python -m suite.run --manifest suite/suite.v1.yaml --output readouts/ra-v2_2026-11-20.md
```

What the orchestrator enforces at startup, before any model call:

- Every dataset SHA matches the on-disk file.
- Every prompt SHA matches the on-disk file.
- The sandbox image digest is reachable (`docker pull @sha256:...`).
- The SymPy version in the environment matches the manifest.
- The judge model endpoints respond to a ping with the pinned name.

Any mismatch fails the run with a clear error. A product suite that silently drifts mid-run is worse than no suite.

## 3. Validation steps

1. **Capability matrix completeness.** Every capability the product exposes has a row. `not-applicable` rows have a committed reason. CI fails when a capability is added to the product spec without a matrix update.
2. **Gate thresholds are numeric and committed.** `suite.v1.yaml` is validated against a schema that forces every `gates[].threshold` to be a parseable constraint (`>= x`, `<= x`, `abs(x - c) <= y`); strings like "high enough" are rejected.
3. **Pins resolve cleanly.** A dry-run subcommand (`suite.run --check`) verifies every dataset SHA, every prompt SHA, every sandbox digest, every judge model endpoint before the real run. Failures stop the run.
4. **Linked suites exist.** `human_sxs.exercise: mod-106/exercise-04` is required to resolve to a committed path; a dangling reference blocks the suite.
5. **Determinism of observed values.** Two runs of the orchestrator against the same manifest and the same model endpoint produce the same observed values within the committed tolerance per component (temperature=0 where supported; variance for RAG judge noted separately).
6. **Owners exist.** `decision_authority` names at least two distinct individuals (not "team names") and each has a current contact in the manifest's `contacts.yaml` sidecar.
7. **Suite manifest is bumped on change.** `suite_version` follows semver. Any change to a gate threshold, a dataset, a prompt, or the model under test requires a `vX.Y.Z` bump; two readouts referencing the same `suite_version` must have been produced with the same manifest content.
8. **No silent averaging.** The orchestrator refuses to emit a single scalar for the suite. `all_gates_must_pass: true` is the only shippable decision rule; "score of 0.82 is good enough" is not a valid override.
9. **Public benchmark subsets are tagged.** When a component dataset is a slice of a public benchmark, the manifest records the slice definition (hash of selected ids) and flags it in the readout, so a published comparison does not accidentally claim the full benchmark name.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a committed, auditable release gate** that would survive a reviewer who shows up three months later.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Capability matrix exists and marks every capability `applicable` / `not-applicable` with a reason | 1 | `suite/capability_matrix.md`; CI enforces one-line justification per row. |
| R2 | Suite manifest pins dataset SHAs, prompt SHAs, sandbox digests, judge model, SymPy version, seed | 2 | `suite.v1.yaml`; `suite.run --check` passes end-to-end. |
| R3 | Every gate has a numeric threshold; no soft-pass language | 2 | Schema check; all thresholds parse as constraints. |
| R4 | Every non-obvious threshold has a committed rationale | 1 | `rationale:` field present where threshold is not an industry standard. |
| R5 | Ship decision is AND of all gates; a single failing gate blocks ship | 1 | `all_gates_must_pass: true`; readout decision reflects it. |
| R6 | Decision authority is a named individual with a committed contact | 1 | `decision_authority` in the manifest; sidecar has current emails. |
| R7 | Linked suites (safety, human eval) are referenced, not duplicated | 1 | `exercise:` fields that resolve to existing solution paths. |
| R8 | Suite version follows semver; readouts cite the suite version | 1 | `suite_version:` in both the manifest and the readout header. |

**Passing bar:** 7 / 10. R5 is non-negotiable — a suite that can be ship-approved on an average is not a release gate.

Reviewer checklist:

- [ ] Every row in the capability matrix has a reason, including `not-applicable` rows.
- [ ] Every gate threshold is numeric; no free-text thresholds.
- [ ] Rationale is committed for thresholds that are not external standards.
- [ ] `all_gates_must_pass: true`; the readout decision is the AND.
- [ ] Decision authority is a named individual; a team name alone is a fail.
- [ ] Linked suites resolve to real paths and are version-pinned.
- [ ] Datasets, prompts, sandbox images, judge model, SymPy version, seed are all pinned in the manifest.
- [ ] The readout header has `suite_version` and `run_id`.
- [ ] A failing gate opens a tracked issue; the readout links it.
- [ ] A public-benchmark slice is tagged as a slice, not reported under the full benchmark name.

## 5. Common mistakes

- **One suite number.** Averaging across components into "suite score = 0.78" lets a safety gate get outvoted by a cheap retrieval gain. Report per-component; AND the gates.
- **Soft thresholds.** "At least as good as prod" / "reasonably high." The next release regresses a rounding amount; nobody can tell if the gate fired. Commit numeric thresholds.
- **No "not-applicable" row.** The product does not emit bounding boxes; the matrix omits grounding. Someone adds a bounding-box feature; the suite does not grow a gate. Mark `not-applicable` explicitly so coverage changes are visible.
- **Suite version not bumped on threshold change.** A gate drops from `>= 0.70` to `>= 0.65` because last release barely passed. Two consecutive readouts cite the same `suite_version` with different pass criteria. Bump semver on any manifest change.
- **Owners are teams, not people.** `decision_authority: eval team`. A bad gate sits for weeks because no one owns it. Name individuals; keep contacts current.
- **Judge and generator are the same model.** The suite's RAG judge is the model under test. The judge agrees with the generator out of style, not accuracy. Use a separately-pinned judge or at minimum a second judge in follow-up.
- **Public benchmark slice reported as full benchmark.** The suite uses 50 items from a 2k-item public benchmark; the readout says "accuracy on <Benchmark Name>" and the number looks competitive. Tag the slice.
- **Linked suites duplicated instead of referenced.** The product suite copies safety thresholds from the mod-109 suite. The two drift. Reference, do not copy.
- **Thresholds set after the numbers.** A release's results are collected; thresholds are then adjusted to pass. The suite became a confirmation ritual. Commit thresholds; if the model cannot meet them, open a tracked issue and block the release.
- **Averaging over seeds / runs without reporting variance.** A single rerun of RAG with a different seed shifts faithfulness by 0.05. The gate oscillates across runs. Report observed value *and* seed; rerun on failure with the same seed to distinguish variance from regression.
- **Readouts without a `run_id`.** Two readouts from the same day exist; neither can be unambiguously tied to the model binary or the suite commit. Every run_id includes the model id, the suite version, and the date.
- **Silent ship on "mostly green."** 12 gates pass, 1 fails, the ship goes anyway because "it's small." The one failing gate is the one that compounds across millions of user turns. AND the gates; the fix is a rerun, not an override.
- **Suite evolution without a changelog.** A gate is removed because it was "too strict." Nobody can tell three months later why the regression started. Keep a per-version changelog in `suite/CHANGELOG.md`; every version bump adds an entry.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires measurements tied to operational context; the capability matrix and per-component gates are the direct operationalization. The `MANAGE` function requires risk decisions to be documented and tied to named decision makers; the manifest's `decision_authority` and the readout's named follow-up owner are the direct operationalization.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. A product eval that omits a capability-matrix row for an exposed capability leaves a surface undefined; every ML Top 10 risk hides more easily on undefined surfaces. The capability matrix is the smallest control that forces coverage decisions to be explicit.
- MITRE ATLAS — <https://atlas.mitre.org/>. An attacker reading the suite manifest learns where the gates *are not*. The committed capability matrix forecloses the easiest avenue — attacking an untested capability — and the named owner on a failing gate forecloses the next easiest — relying on a gate nobody will act on.

<!-- Local exercise context: the "ra-v2 Research Assistant" product sketch, the specific component evals in the capability matrix, the numeric gate thresholds (pass@1 >= 0.45, accuracy_strict >= 0.65, faithfulness >= 0.75, mean_soft_acc >= 0.60, win_rate >= 0.52, etc.), and the readout template are illustrative defaults for a general-purpose internal assistant. Rewrite them for the product spec, user population, and risk tier of your own system before adopting. The component evals bundled here are the subjects of [exercise-01](../exercise-01-pass-at-k-with-sandbox-execution/SOLUTION.md) (code), [exercise-02](../exercise-02-math-eval-with-robust-extraction/SOLUTION.md) (math), [exercise-03](../exercise-03-rag-eval-with-ragas-and-trulens/SOLUTION.md) (RAG), and [exercise-04](../exercise-04-multimodal-vqa-and-grounding-eval/SOLUTION.md) (multimodal). The human-SxS component references the mod-106 solutions set, specifically the attention-check and adjudication exercises. The safety / red-team suite referenced from the capability matrix is the subject of the mod-109 solutions set. -->
