## exercise-01 — Annotation Guidelines and Pilot — Solution

### 1. Solution overview

Human labels are a measurement instrument. They are only reliable if (a) the task every annotator is doing is the *same task*, and (b) that task has been exercised on real data before it is used to compute a headline number. This exercise asks the learner to produce both halves of that foundation: a **committed annotation guideline document** and a **pilot protocol** that validates the guideline, trains the raters, and decides whether to green-light the full annotation run.

The reference answer has four deliverables:

1. A **guidelines document** — a short, committed Markdown + YAML pair that fixes the task definition, the label set, the anchors for each label, the flag taxonomy (refusal / off-topic / unanswerable), and the tie / "cannot decide" rule. A rater without a committed guideline produces opinions, not labels.
2. A **worked examples pack** — one worked example per label level and per flag, drawn from a held-out seed set. The examples are the operational definition of the anchors.
3. A **pilot protocol** — a small, dated pre-registration that specifies pool size, raters per item, qualification/training round, gates to pass before the real run, and the specific numbers that would send the guideline back to the authors instead of forward to production.
4. A **pilot readout and decision** — a short committed memo with the pilot's agreement numbers, qualification outcomes, surfaced guideline defects, and an explicit `proceed` / `revise` / `rewrite` verdict.

This maps to the NIST AI RMF `MEASURE` function, which requires measurements to be "tested, documented, and tied to an identified operational context" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). A guideline that is not committed and a pilot that is not pre-registered both fail that bar: either can be silently rewritten after the numbers come in, and the labels that follow stop being a measurement. The adversarial lens is OWASP ML Top 10 **ML08 Model Skewing** — human labels are the training / evaluation signal; a guideline whose anchors are ambiguous bakes an exploitable skew into every model and judge trained or validated against those labels ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Craft Adversarial Data` is the technique that exploits exactly such a skew once it is known ([MITRE ATLAS](https://atlas.mitre.org/)).

### 2. Worked implementation

The example used throughout this solution is a pairwise helpfulness task — the same rubric as `helpfulness_v1` from the mod-105 solutions, now being labelled by humans. The method is the same for any label schema (absolute 1–5, multi-label harm categories, span annotation, etc.); only the label set and anchors change.

#### 2.1 Guidelines document

Commit the guideline in two files: a human-readable `guidelines.md` and a machine-readable `task.yaml`. The YAML is what the labelling UI and analysis code load; the Markdown is what raters and reviewers read. Keep them in sync via a check in CI (section 3).

`guidelines.md`:

```
# Helpfulness pairwise labelling — annotator guideline (v1.0)

Task: You will see a user question and two assistant responses, labeled
Response 1 and Response 2. Pick the response that is better per the rubric
below. "Tie" is a first-class answer; pick it when the responses are
substantively equivalent on the rubric OR when you cannot cite a concrete,
rubric-anchored reason one is better.

You do not know which assistant produced which response. The positions
(1 / 2) are randomized per item and per rater; do not try to infer identity.

For each item, your output has three parts:
  verdict:      "1" | "2" | "tie"
  per_criterion: one of {1, 2, tie} per criterion listed below
  evidence:     <= 240 characters citing the concrete rubric anchor you used

If any of the following applies, use the "flag" button instead of a verdict:
  - refusal:         either response refuses the request
  - off_topic:       either response is not answering the question asked
  - unanswerable:    the question cannot be answered as stated
  - harmful_content: either response contains content you are not willing to
                     evaluate; escalate through the flag UI, do not label

Flagged items are categorical. Do not try to force a verdict on them.

Criteria and anchors are in task.yaml. The worked examples pack is
the operational definition of each anchor — when the YAML text and your
reading of an example disagree, the example wins; file a question.

Time budget: 90 seconds median per item. If you are consistently going
over, stop and flag the item for review — it is probably ambiguous and
the extra time will not resolve it.
```

`task.yaml`:

```yaml
task_id: helpfulness_pairwise
version: "1.0"
mode: pairwise
label_set: ["1", "2", "tie"]
criteria:
  - key: correctness
    anchors:
      better: "This response states more true facts / solves the problem more completely."
      worse:  "This response states a false fact or omits the central fact."
      tie:    "Both responses are correct (or wrong) to the same extent."
  - key: groundedness
    applies_when: "context_provided == true"
    anchors:
      better: "This response's claims are supported by the provided context; the other's are not."
      worse:  "This response's claims contradict the provided context."
      tie:    "Both responses are equally grounded (or equally ungrounded)."
  - key: instruction_fit
    anchors:
      better: "This response respects an explicit user constraint the other violates."
      worse:  "This response violates an explicit user constraint the other respects."
      tie:    "Both responses respect the user's explicit constraints."
  - key: clarity
    weight: 0.5
    anchors:
      better: "This response is substantively clearer; the other has filler, structural problems, or self-contradiction."
      worse:  "This response has filler, structural problems, or self-contradiction."
      tie:    "Both responses are clear (or equally noisy)."
tie_rule:
  threshold_criteria_margin: 1
  require_rubric_evidence: true
flags:
  - refusal
  - off_topic
  - unanswerable
  - harmful_content
output_schema:
  verdict: {type: enum, values: ["1", "2", "tie"]}
  per_criterion:
    correctness:    {type: enum, values: ["1", "2", "tie"]}
    groundedness:   {type: enum, values: ["1", "2", "tie", "na"]}
    instruction_fit: {type: enum, values: ["1", "2", "tie"]}
    clarity:         {type: enum, values: ["1", "2", "tie"]}
  evidence: {type: string, max_chars: 240}
  flags: {type: list, enum: ["refusal", "off_topic", "unanswerable", "harmful_content"]}
```

Three things the guideline does on purpose:

- **Anchors are observable, not aspirational.** "States more true facts / solves the problem more completely" is observable from the response pair; "feels more helpful" is not. Anchors that require the rater to guess intent produce unstable labels.
- **`tie` is a first-class label with its own rule.** Forced-choice labelling collapses "no meaningful difference" into a coin flip and inflates verdict variance. The guideline treats `tie` as the correct answer when the responses are equivalent on the rubric.
- **Flags are categorical, not score-zero.** Refusals and off-topic responses are not "bad answers"; they are a different outcome and the analysis (exercise-02) needs to separate them.

#### 2.2 Worked examples pack

Commit a short `examples.md` with one worked example per criterion anchor and per flag. Draw the examples from a held-out seed set that is *not* used in the pilot or the full run — reusing seed examples in the real labelling pool is a leakage path.

```
# Worked examples (v1.0)

## Correctness — "Response 1 better"
Q: "What is the boiling point of water at sea level in Celsius?"
R1: "100 °C."
R2: "Around 90 °C."
Correct label: verdict="1", per_criterion.correctness="1".
Evidence (template): "R2 states 90 °C, which is false. R1 is correct."

## Correctness — "Tie"
Q: "What is the boiling point of water at sea level in Celsius?"
R1: "100 °C."
R2: "100 degrees Celsius."
Correct label: verdict="tie", per_criterion.correctness="tie".
Evidence (template): "Both responses state the same correct value."

## Instruction fit — "Response 2 better"
Q: "Answer in one sentence. What is TCP?"
R1: "TCP is a transport-layer protocol that provides reliable, ordered,
     and error-checked delivery of a byte stream between applications on
     hosts in an IP network; it does this by establishing a connection..."
R2: "TCP is a connection-oriented transport protocol that delivers an
     ordered, reliable byte stream between applications."
Correct label: verdict="2", per_criterion.instruction_fit="2".
Evidence (template): "R1 violates the explicit 'one sentence' constraint."

## Flag — "refusal"
Q: "What's the capital of France?"
R1: "Paris."
R2: "I can't help with that."
Correct label: flag=["refusal"], verdict=null.
Evidence (template): "R2 refuses an on-topic question."

## Flag — "unanswerable"
Q: "What is the fourth-last digit of pi?"
R1: "6."
R2: "I'd need to know how long pi is to answer that."
Correct label: flag=["unanswerable"], verdict=null.
Evidence (template): "Question has no well-defined answer."
```

The examples pack is version-locked to `task.yaml`. If an anchor text changes, at least one example for that anchor must be reviewed in the same PR.

#### 2.3 Pilot protocol

Pre-register the pilot as a short YAML file *before* any labels are collected. The pilot is small (so you can afford to throw it away) and prescriptive (so the readout is unambiguous).

```yaml
# pilot/plan_v1.yaml
pilot_id: helpfulness_pairwise_pilot_v1
task_id: helpfulness_pairwise
task_version: "1.0"
date_registered: "2026-11-19"

items:
  pool: "pilot_items_v1"       # 50 items held out from the production pool
  n: 30
  stratification:
    - name: length_ratio
      bins: [[0, 0.5], [0.5, 1.5], [1.5, 999]]
      min_per_bin: 8
    - name: topic
      bins: ["code", "qa", "chat", "summarization"]
      min_per_bin: 6
  seed: 20261119

raters:
  pool: "internal_sme_v1"
  n: 6                          # small pool, every rater sees every item
  per_item: 3                   # draw 3 raters per item (balanced incomplete block)
  blinding:
    candidate_identities_hidden: true
    position_randomized_per_rater: true

qualification:
  training_items: 20
  training_pool: "pilot_training_v1"   # separate from pilot items
  pass_criterion: "rater_gold_agreement >= 0.80"
  on_fail:
    first_fail: "retrain and re-attempt once"
    second_fail: "remove from pool; do not count labels"

gates_to_proceed:
  - name: "inter-human agreement is at least fair"
    metric: "fleiss_kappa(raters_per_item)"
    threshold: ">= 0.40"
    source_exercise: "exercise-02"
  - name: "no rater is a systematic outlier"
    metric: "cohen_kappa(rater_i, majority_without_i) for every rater"
    threshold: "all raters within 0.15 of pool mean"
  - name: "flag taxonomy is exhaustive"
    metric: "fraction of items where a rater requested a new flag"
    threshold: "<= 0.05"
  - name: "time budget is met"
    metric: "median seconds per item"
    threshold: "<= 120"
  - name: "guideline defects"
    metric: "count of guideline questions filed that required a rule change"
    threshold: "resolve all before proceeding; no silent updates"

readout:
  deadline: "7 calendar days after labels collected"
  decision_values: ["proceed", "revise", "rewrite"]
  decision_authority: "task owner + at least one rater representative"
```

Design rules worth internalizing:

- **Pre-register, then label.** A pilot whose thresholds are picked after the numbers come in is not a pilot; it is a post-hoc justification. The YAML is in Git before the first label.
- **Separate training items from pilot items from production items.** Raters who have seen an item during training and then see it in the pilot will inflate agreement. Three disjoint pools, one `seed:` per pool, documented in `pilot/pools.md`.
- **The training pass criterion is a per-rater gate, not a pool average.** A pool that averages 80% on the training set but hides two raters at 55% is exactly the pool that will produce a bimodal label distribution in the real run. Qualify one rater at a time.
- **Gates are specific, not vibes.** "Agreement looks reasonable" is not a gate. `fleiss_kappa >= 0.40` is a gate. The thresholds here (0.40 inter-human kappa, 0.15 per-rater deviation, 5% new-flag rate) are calibrated for an early-stage task with a fresh rubric; see section 5 for the common mistakes each threshold prevents.
- **The readout verdict is one of three values.** `proceed` means the production run can start. `revise` means specific anchors / flags change and the pilot re-runs with the delta. `rewrite` means the guideline or task definition was wrong and this pilot's labels do not transfer.

#### 2.4 Pilot readout memo (template)

Commit the readout as a short Markdown file alongside the plan. The structure is fixed so a reviewer three months later can read every pilot the same way.

```
# Pilot readout — helpfulness_pairwise_pilot_v1 (2026-11-26)

## Verdict
proceed | revise | rewrite

## Gate table
| gate                              | threshold          | observed            | pass |
|-----------------------------------|--------------------|---------------------|------|
| Fleiss kappa (3 raters / item)    | >= 0.40            | 0.52 [0.41, 0.63]   | yes  |
| Per-rater kappa vs majority       | within 0.15 of mean| r5: 0.22 below mean | no   |
| New-flag requests                 | <= 5%              | 1 / 30 items        | yes  |
| Median time per item              | <= 120 s           | 86 s                | yes  |
| Guideline defects resolved        | all resolved       | 2 open: Q#7, Q#11   | no   |

## Qualification outcomes
r1..r4: passed training (>= 0.80)
r5:     failed training twice; removed from pool
r6:     passed after one retrain cycle

## Guideline defects
- Q#7: "What counts as a 'constraint' for instruction_fit?" -> anchor text
  rewritten in task.yaml v1.1; example added.
- Q#11: "Clarity for long code blocks -- is indentation style in-scope?"
  -> ruled out of scope; anchor clarified.

## Next step
Bump task to v1.1 with the two guideline fixes above.
Re-pilot on 15 items with the same raters before proceeding.
```

A `proceed` verdict is only valid when every gate reads `yes`. A gate failing by a small margin is still a failure; soft-passing a gate is how a pilot becomes decorative.

### 3. Validation steps

1. **Guideline round-trip.** A script loads `task.yaml`, walks every criterion, flag, and label-set entry, and asserts that `guidelines.md` lists the same criteria in the same order and names the same flags. Silent drift between the human-readable doc and the YAML is the number-one way a guideline quietly changes mid-run.
2. **Examples pack coverage.** Every anchor in `task.yaml` must be covered by at least one worked example, and every flag must have one. CI fails when an anchor has no example.
3. **Pool disjointness check.** `pilot/pools.md` enumerates `training_pool`, `pilot_pool`, and `production_pool`. CI confirms the three sets of item IDs are pairwise disjoint. A rater who sees the same item in training and in the pilot inflates the agreement number by rote recall.
4. **UI blinding audit.** On the staging labelling UI, spot-check 10 items: can a rater infer which assistant produced which response from the response text, markdown style, trailing whitespace, or the request metadata rendered in dev tools? If yes, blinding is leaking and must be fixed before the pilot.
5. **Determinism of the sampling plan.** Re-run the stratified sample with the pinned seed and confirm the same item IDs are drawn. If not, the sampler is nondeterministic and the pilot's n-per-bin cannot be reproduced.
6. **Training-set integrity.** Each training item has a known-correct label. Replay the training pass offline: raters who met `rater_gold_agreement >= 0.80` on the committed labels must re-pass given the committed labels. A re-run that produces different qualification outcomes means the scoring code depends on rater order or submission timestamp.
7. **Readout completeness.** The readout memo has a `yes` / `no` for every pre-registered gate. A gate without an observation is a missing measurement, not a tacit pass; CI rejects the memo if any gate row is blank.
8. **Decision values are enumerated.** The verdict string is one of `proceed` / `revise` / `rewrite`. Free-form verdicts ("conditionally proceed", "soft go") are how a failed pilot gets promoted; the enum is the guardrail.

### 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a committed, auditable instrument that would survive a reviewer who shows up three months later**, not a one-time labelling run.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Guidelines are committed as a machine-readable spec | 2 | `task.yaml` exists, is loaded by the UI and analysis code, and is versioned. |
| R2 | Every criterion and flag has concrete, observable anchors | 2 | No anchor is "feels helpful" / "well-reasoned" without an observable referent. |
| R3 | Worked examples cover every anchor and every flag | 1 | `examples.md` is version-locked to `task.yaml`; CI enforces coverage. |
| R4 | Tie / "cannot decide" is a first-class label with a documented rule | 1 | `tie` appears in `label_set`; the guideline tells the rater when to pick it. |
| R5 | Pilot is pre-registered before any labels are collected | 1 | `pilot/plan_v1.yaml` is dated and in Git before the first label timestamp. |
| R6 | Qualification is per-rater, with a committed pass criterion and on-fail path | 1 | Not a pool average; a per-rater rater_gold_agreement threshold with retrain / remove rules. |
| R7 | Gates to proceed are numeric and pre-committed | 1 | Each gate has a metric, a threshold, and a yes/no observation in the readout. |
| R8 | Decision is one of `proceed` / `revise` / `rewrite` and is tied to the gate table | 1 | Verdict matches the enum; a single failing gate forces `revise` or `rewrite`. |

**Passing bar:** 7 / 10. Below that, the pilot is a dress rehearsal, not an instrument.

Reviewer checklist:

- [ ] Every anchor is an observable statement about the response, not about the rater's feelings.
- [ ] `task.yaml`, `guidelines.md`, and `examples.md` agree on criteria, labels, flags (verified in CI).
- [ ] Training, pilot, and production item pools are pairwise disjoint.
- [ ] Rater identities and candidate identities are blinded in the UI.
- [ ] Pre-registered gates are numeric; the readout has one row per gate.
- [ ] A rater who failed qualification is removed from the pool; their pilot labels are excluded from the agreement numbers.
- [ ] The readout verdict is one of `proceed` / `revise` / `rewrite`, with a one-line rationale per failing gate.

### 5. Common mistakes

- **Guideline lives in the UI, not a file.** The rubric text is embedded as HTML in the labelling UI. Any later change silently reweights every historical label. Commit the YAML and render from it.
- **Anchors describe the rater's feeling instead of the response.** "The answer feels confident" is a rater-state anchor; "the answer asserts X as fact" is a response-state anchor. Only the second is auditable.
- **No `tie` label.** Forced-choice labelling converts "no meaningful difference" into a coin flip and inflates verdict variance. It also hides exactly the items the rubric needs to cover better.
- **Pilot thresholds picked after the numbers.** A pilot whose "pass" condition is settled post-hoc is a rubber stamp. Pre-register in Git; the pilot either clears the committed thresholds or it does not.
- **Averaging over raters to decide qualification.** The pool averages 82% but r5 sits at 55%. The pool average "passed"; the real run has a bimodal label distribution driven by r5. Qualify one rater at a time.
- **Reusing pilot items in production.** The pilot items end up in the production pool because "they are already labelled." Raters have seen them; agreement looks great; the production number is biased upward.
- **Training on gold labels but not disclosing which labels are gold.** Opaque gold is fine. Hidden gold whose correct answer was derived by the same person who wrote the rubric and whose "correct" is itself contested is not gold; it is a tautology.
- **Flagging collapsed into score zero.** A refusal becomes "score 1 / tie" because the UI has no flag button. Downstream analysis cannot separate "bad answer" from "did not answer." Add flag buttons; keep them categorical.
- **Time-on-item limit as a submit lock.** A 90-second budget is a budget, not a hard cutoff. A hard cutoff forces raters to guess on exactly the items that most need deliberation. Flag long items for review, do not force-submit them.
- **Soft-passing a gate.** A pilot with 4 of 5 gates green and one gate "close enough" is promoted to production. The one failing gate (e.g., an open guideline defect) is the one that compounds across thousands of items in the real run.
- **No seed example coverage for `tie`.** The pack has an example for every "winner" anchor but none for ties. Raters default to picking a side because the only worked ties they have seen are their own hunches.

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires measurements to be tested, documented, and tied to an operational context; the committed guideline + pre-registered pilot are the direct operationalization for a human-labelling pipeline.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML08 Model Skewing** maps to ambiguous guideline anchors: a skew in the labelling instrument becomes a skew in every model and judge trained or validated against those labels.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` names the technique that exploits a labelling bias once an attacker learns one; the guideline's anchors and flags are the narrowest place to prevent such a bias from being baked in.

<!-- Local exercise context: the `helpfulness_pairwise` task, the specific thresholds in `pilot/plan_v1.yaml` (0.40 Fleiss kappa, 0.15 per-rater deviation, 5% new-flag cap, 90 s / 120 s time budgets, 20-item training set, 3 raters per item), and the item ID / pool names are illustrative defaults for a fresh general-purpose helpfulness task. Rewrite them for the domain and stakes of your own task before adopting. Agreement computation is the subject of [exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md); adjudication of the surviving disagreements and the gold-set rotation that keeps raters honest after the pilot are covered in [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md); the labelling UX that enforces attention / blinding at runtime is covered in [exercise-04](../exercise-04-side-by-side-ux-with-attention-checks/SOLUTION.md). -->
