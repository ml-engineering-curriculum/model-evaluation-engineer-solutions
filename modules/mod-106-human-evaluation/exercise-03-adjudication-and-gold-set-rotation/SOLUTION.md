## exercise-03 — Adjudication Procedure and Gold-Set Rotation — Solution

### 1. Solution overview

The upstream labelling pipeline produces a set of rater verdicts per item ([exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md)) and a structured inventory of disagreements ([exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md)). This exercise is about the two mechanisms that turn those labels into a durable, trustworthy reference: a committed **adjudication procedure** that resolves disagreements into a single human-authoritative label, and a **gold-set rotation** that keeps raters calibrated over the lifetime of the labelling program.

The reference answer has four deliverables:

1. An **adjudication procedure** — a committed, pre-registered policy that specifies when an item is adjudicated (quorum rules), who adjudicates it (role separation), what evidence they see, and what the recorded output looks like. Ad-hoc "a senior rater took another look" is not an adjudication procedure.
2. A **gold-set construction protocol** — how items become gold, who signs them off, how the gold pool is kept fresh, and how its item IDs are prevented from leaking back into the production labelling pool.
3. A **gold-set rotation schedule** — the cadence at which gold items are injected into the live labelling stream, per-rater and per-pool, with the per-rater performance metrics that are computed from the injections.
4. A **rater and rubric drift contract** — numeric thresholds that read off the rotation metrics and decide, per rater and for the pool as a whole, whether to keep labelling, retrain, pause, or rewrite the guideline. Drift without a contract is a dashboard; the contract is what makes it a control.

This maps to the NIST AI RMF `MANAGE` and `MEASURE` functions, which together require continuous measurement of reliability with documented response thresholds ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). Adjudication is the mechanism that produces the reference signal; gold-set rotation is the mechanism that measures the labelling system against that reference over time. The adversarial lens is OWASP ML Top 10 **ML02 Data Poisoning** (adversarially constructed or compromised labels that end up in the gold set silently degrade every downstream evaluation) and **ML08 Model Skewing** (undetected rater drift is a slow-moving skew in the evaluation instrument) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Craft Adversarial Data` describes the attacker who exploits an unrotated or unaudited gold set ([MITRE ATLAS](https://atlas.mitre.org/)).

### 2. Worked implementation

The running example remains the pairwise helpfulness task from [exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md), with 3 raters per item and label set `{"1", "2", "tie"}`. The same machinery generalizes; only the tie and quorum rules change per label type.

#### 2.1 Adjudication procedure

Commit the procedure as `adjudication/policy.yaml`. The file is referenced by the queueing code; a change to the policy is a code change, not an opinion.

```yaml
# adjudication/policy.yaml
task_id: helpfulness_pairwise
task_version: "1.0"
quorum_rule:
  majority_of_three:
    enters_adjudication_when:
      - "no label held by 2 or more raters"            # 1-1-1 across {1, 2, tie}
      - "any rater submitted a flag that disagrees with any non-flag label"
    accepts_without_adjudication_when:
      - "2 of 3 raters agree AND no rater filed a flag AND no rater left evidence contradicting the majority"

adjudicator:
  pool: "task_rubric_authors"
  must_not_be: "a rater whose label is under review"   # role separation
  min_per_item: 1
  blinding:
    sees_rater_identities: false
    sees_rater_evidence: true      # the free-text justifications
    sees_rater_labels: true

evidence_pack:
  - original_item
  - rater_labels (anonymised)
  - rater_per_criterion
  - rater_evidence_strings
  - item_metadata.slice_tags
  - upstream_flags

adjudicator_output:
  verdict: {type: enum, values: ["1", "2", "tie", "flag:refusal", "flag:off_topic", "flag:unanswerable", "flag:harmful_content"]}
  disagreement_label:
    required: true
    values: ["rater_error", "guideline_gap", "ambiguous_item", "item_defect"]
  rubric_citation: {type: string, required: true}
  guideline_patch_needed:
    required_when: "disagreement_label == 'guideline_gap'"
    type: string
    description: "proposed text change to task.yaml or examples.md"
  tombstone_item:
    required_when: "disagreement_label == 'item_defect'"
    type: boolean
    default: true

escalation:
  when: "two adjudicators reviewing the same item disagree"
  who: "task owner + second rubric author"
  output: "same schema as single adjudicator; record both prior verdicts"

timing:
  adjudicate_within: "7 calendar days of item marked for adjudication"
  overdue_action: "pause gold-set promotion for the task until queue is drained"

storage:
  record_schema: "adjudication/record.schema.json"
  append_only: true
  retains_original_rater_labels: true   # never overwrite raw labels with the adjudicated verdict
```

Rules worth internalizing:

- **Adjudicator is a different role from rater.** A rater adjudicating their own disagreements is not an adjudication, it is a vote recount. The adjudicator pool is explicitly named (`task_rubric_authors`) and is forbidden from adjudicating an item where their own label is under review.
- **Adjudicators see rater evidence, not rater identities.** Named-rater anchoring is a well-known bias path; evidence strings carry the content without the name.
- **Every adjudication writes a `disagreement_label`.** The point estimate on which rater was "right" is almost never the interesting output. The disagreement classification is what drives the guideline-fix / rater-retrain / item-defect decisions.
- **The original rater labels are never overwritten.** The adjudicated verdict is a separate record. Overwriting the raw labels makes the agreement computations from [exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md) silently unreproducible after adjudication.
- **A `guideline_gap` disagreement must propose a patch.** A gap flagged with no proposed text is a defect report, not a decision; the point of adjudication is to produce the next guideline, not to reopen the ticket.

The record schema (append-only JSONL, one line per adjudicated item) carries the full story:

```json
{
  "run_id": "2026-11-26-helpfulness-run004",
  "item_id": "q-00318",
  "task_id": "helpfulness_pairwise",
  "task_version": "1.0",
  "rater_labels": [
    {"rater": "r_anon_a", "verdict": "1", "evidence": "..."},
    {"rater": "r_anon_b", "verdict": "2", "evidence": "..."},
    {"rater": "r_anon_c", "verdict": "tie", "evidence": "..."}
  ],
  "flags_from_raters": [],
  "adjudicator": {"role": "rubric_author", "id_anonymised": "adj_02"},
  "verdict": "1",
  "disagreement_label": "rater_error",
  "rubric_citation": "correctness anchor 'better'",
  "guideline_patch_needed": null,
  "tombstone_item": false,
  "adjudicated_at": "2026-11-26T15:02:07Z"
}
```

#### 2.2 Gold-set construction protocol

An item becomes a gold item only after it has gone all the way through the adjudication pipeline above with an outcome compatible with a durable truth. Commit the acceptance rules in `gold/construction.yaml`:

```yaml
# gold/construction.yaml
sources:
  - adjudicated_items:
      require:
        - "disagreement_label in {rater_error, ambiguous_item}"
        - "adjudicator confidence recorded as 'high'"
        - "item has at least 3 original rater labels"
  - uncontested_items:
      require:
        - "3 of 3 rater agreement on the production run"
        - "no rater left an evidence string citing an anchor gap"
        - "random sampled at a rate of 20% of eligible items"

exclusions:
  - "disagreement_label == 'guideline_gap'"      # the gap is being fixed; item is unstable
  - "disagreement_label == 'item_defect'"
  - "any rater flagged harmful_content"

signoff:
  min_approvers: 2
  roles: ["task_owner", "rubric_author"]
  recorded_in: "gold/manifest.jsonl"             # append-only

pool_budget:
  min_size: 150
  target_size: 400
  refresh_rate_items_per_month: 40               # see rotation schedule below

leakage_controls:
  manifest_access: "principals in task_owner role only"
  rater_access: "never direct; gold items reach raters only through the labelling UI's injection path"
  id_hashing:
    required: true
    rotate_salt_every_days: 30
    rationale: "a rater who sees the same item_id twice can memorise it; rotate hashes so the re-encounter looks new"
  no_examples_leakage: "items that appear in examples.md (exercise-01) are never promoted to gold"
```

Three things the protocol does on purpose:

- **Gold is not "the majority label on easy items."** Easy-but-biased items are exactly where a rubric's blind spot concentrates; uncontested items are sampled at 20% precisely to avoid saturating the gold pool with the low-information cases.
- **Ambiguous items can be gold, rater-error items can be gold, guideline-gap items cannot.** An item whose "correct" label is that the rubric does not cover it is not a reference; it is a backlog item for the guideline.
- **Two-approver signoff on gold is required.** Single-author gold is how a single person's rubric reading becomes "the truth" against which every rater is measured. Two approvers in different roles is the floor.
- **Leakage controls include id hashing with salt rotation.** A rater who memorises `item_id: q-00318 = "1"` passes the gold check by rote, which destroys the signal. Rotating the hash salt makes the re-encounter look new.

#### 2.3 Rotation schedule

Commit the rotation schedule as `gold/rotation.yaml`. The injection code loads it; the knobs are not UI settings.

```yaml
# gold/rotation.yaml
cadence:
  per_rater_injection_rate: 0.08                 # 8% of a rater's items are gold, on average
  minimum_gold_per_rater_per_week: 15
  maximum_consecutive_non_gold: 40               # guarantee a gold within every 40 items
  per_batch_mixture:
    ensure_each_rater_batch_includes_gold: true
    position_distribution: "uniform within batch; never stacked at the start"

sampling:
  per_rater:
    weight_recent_misses_higher: true            # if a rater missed on slice X, next gold is more likely from slice X
    stratify_over: ["label", "slice_tags"]
  pool_wide:
    freshness_fraction: 0.25                     # at least 25% of weekly gold draws are items added in the last 90 days

rotation_of_items_in_the_pool:
  retire_after:
    - "5 appearances in front of the same rater"
    - "gold item itself has been contested in an adjudication re-review"
  readmission:
    allowed_after_days: 180
    requires_re_signoff: true

seed:
  value: 20261119
  rotation_salt_days: 30
```

Why the specific knobs:

- **Injection rate 8%, floor 15 per rater per week.** 8% balances cost against drift signal; the per-week floor prevents a short-shift rater from never seeing a gold item. 15 items is roughly the minimum sample size at which a per-rater pass rate has a usable CI (section 2.4).
- **Position uniform, never stacked.** Raters who learn that "gold shows up in the first 5 items of each batch" stop being measured, which is the whole point of injection.
- **Stratify over labels and slices.** A gold pool that is 70% `"1"` labels biases the per-rater metric toward raters who default to `"1"`. Stratify so each rater's gold history is balanced.
- **Retire after 5 appearances per rater.** Rote memorization sets in; a rater who has seen the same gold item five times is being tested on recall, not on the task.
- **180-day readmission + re-signoff.** The guideline, the pool, and the item meaning drift. Readmission is not automatic.

#### 2.4 Per-rater metrics from rotation

For every rater, roll up the gold outcomes weekly:

```python
# gold/metrics.py
from collections import Counter


def per_rater_metrics(gold_outcomes, categories=("1", "2", "tie")):
    """gold_outcomes: list of dicts with keys {rater, verdict, gold_label, slice_tags}.
    Returns per-rater pass rate, per-slice pass rate, per-category confusion, and a
    Wilson CI for the overall pass rate.
    """
    per = {}
    for row in gold_outcomes:
        r = row["rater"]
        p = per.setdefault(r, {"n": 0, "hits": 0, "per_slice": Counter(), "slice_n": Counter(),
                               "conf": {c: Counter() for c in categories}})
        hit = row["verdict"] == row["gold_label"]
        p["n"] += 1
        p["hits"] += int(hit)
        for s in row.get("slice_tags", []):
            p["per_slice"][s] += int(hit)
            p["slice_n"][s] += 1
        p["conf"][row["gold_label"]][row["verdict"]] += 1

    def wilson(h, n, z=1.96):
        if n == 0:
            return (float("nan"), float("nan"))
        phat = h / n
        denom = 1 + z * z / n
        center = (phat + z * z / (2 * n)) / denom
        half = z * ((phat * (1 - phat) / n + z * z / (4 * n * n)) ** 0.5) / denom
        return (center - half, center + half)

    out = {}
    for r, p in per.items():
        lo, hi = wilson(p["hits"], p["n"])
        out[r] = {
            "n": p["n"],
            "pass_rate": p["hits"] / p["n"] if p["n"] else float("nan"),
            "ci95": (lo, hi),
            "per_slice_pass": {
                s: p["per_slice"][s] / p["slice_n"][s] for s in p["slice_n"]
            },
            "confusion": p["conf"],
        }
    return out
```

Numbers that go on the per-rater dashboard:

- `pass_rate` — fraction of gold items the rater labelled correctly in the window.
- Wilson 95% CI on the pass rate.
- Per-slice pass rate — the same number broken down by slice tag; a rater at 0.88 overall who sits at 0.55 on code-topic items has a targeted drift that an aggregate number hides.
- Confusion matrix of rater verdict vs gold label — direction of error, not only magnitude.

#### 2.5 Drift contract

```yaml
# gold/drift_contract.yaml
per_rater:
  continue:
    require:
      - "pass_rate_point >= 0.85"
      - "pass_rate_ci_lower >= 0.75"
      - "no slice with n >= 10 below pass_rate 0.60"
  retrain:
    when:
      - "0.70 <= pass_rate_point < 0.85 OR any slice with n >= 10 below 0.60"
    action:
      - "pause rater from receiving non-gold items until retrain complete"
      - "deliver the rater their own confusion matrix and per-slice pass rate"
      - "re-qualify against pilot training set (exercise-01) before resuming"
  pause:
    when:
      - "pass_rate_point < 0.70 OR pass_rate_ci_upper < 0.75"
    action:
      - "stop sending items to rater"
      - "exclude rater's recent labels from gold-eligible pool until re-qualification"

per_pool:
  guideline_fix_required:
    when:
      - "median per-rater pass_rate dropped by >= 0.05 over the last 4 weeks"
      - "OR the same gold item has been missed by >= 3 distinct raters"
    action:
      - "re-adjudicate the implicated gold items; relabel as guideline_gap if appropriate"
      - "bump task.yaml version and re-pilot (exercise-01)"

attack_signal:
  investigate:
    when:
      - "sudden drop in a single rater's pass_rate on a single slice without a guideline change"
      - "OR a gold item's correct label starts being missed by multiple previously-passing raters simultaneously"
    action:
      - "freeze the implicated gold item; re-signoff from fresh adjudicators"
      - "treat as ML02 (data poisoning) signal until ruled out"
```

The drift contract is not a dashboard; it is a control. The per-rater thresholds, the pool-wide trigger, and the attack signal are each wired to a specific response — retrain, pause, re-pilot, investigate. Numbers without a committed response are decoration.

### 3. Validation steps

1. **Role-separation enforcement.** The adjudication queueing code refuses to assign an item to an adjudicator who appears in `rater_labels`. CI includes a test that constructs the forbidden case and expects a rejection.
2. **Append-only audit trail.** `adjudication/records.jsonl` and `gold/manifest.jsonl` are write-append-only via the application layer; a unit test asserts that overwriting an existing `item_id` raises. An adjudication system that silently overwrites is one that cannot be audited.
3. **Gold-set leakage check.** On every CI run, assert that `set(gold_item_ids) ∩ set(examples_pack_item_ids) == ∅`, and that no `gold_item_id` appears in `training_pool`, `pilot_pool`, or in the non-gold slot of `production_pool`. Gold leakage is the cheapest way to produce a spuriously great pass rate.
4. **Hash-salt rotation.** CI verifies that the salt in `gold/rotation.yaml` is dated and that the previous salt was dropped within the required window. A stuck salt lets raters memorize item IDs.
5. **Injection distribution audit.** Replay a week of injections and confirm the 8% rate, the 15/week floor, the max-40-non-gold spacing, and the uniform-within-batch position. A spike in gold rate at the start of a batch is a UI bug and makes the metric meaningless.
6. **Wilson CI pinning.** Re-running the metrics module on the same outcomes produces bit-identical CIs. If not, the CI code has nondeterminism and the per-rater ladder is irreproducible.
7. **Stratum coverage check.** For each rater, the gold items they have seen in the last 4 weeks cover every committed slice tag; raters who have never seen gold from a slice cannot have that slice's pass rate measured. Alert when a rater has zero-n on a committed slice.
8. **Adjudication SLA check.** The queue dashboard reports age of pending adjudications; the policy's `adjudicate_within` is enforced by pausing gold promotion when the queue exceeds the SLA. A back-dated "resolved" record is caught by the append-only write test.
9. **Guideline-patch coverage.** Every `disagreement_label == 'guideline_gap'` record has a non-empty `guideline_patch_needed`. CI fails if an unpatched gap is older than one pilot cycle (7 days by [exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md) convention).
10. **Round-trip reproducibility.** Given a frozen adjudication log + gold manifest + rotation seed, re-running the injection scheduler produces the same per-rater sequence of gold item IDs (modulo salt rotation).

### 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Adjudication procedure is committed, versioned, and role-separated | 2 | `policy.yaml` exists; adjudicator pool is distinct from rater pool; code enforces the separation. |
| R2 | Every adjudicated item carries a disagreement label and (if applicable) a guideline patch | 2 | JSONL records show `disagreement_label` for 100% of adjudications; `guideline_gap` records have a proposed patch. |
| R3 | Gold-set construction has signoff rules and explicit exclusions | 1 | `gold/construction.yaml` enforces ≥ 2 approvers; `guideline_gap` / `item_defect` items are excluded. |
| R4 | Gold items are isolated from training, pilot, and examples pools | 1 | CI check asserts disjointness; manifest is access-controlled. |
| R5 | Rotation schedule is committed, with rate, floor, spacing, and position rules | 1 | `gold/rotation.yaml`; injection code loads it; replay audit confirms distribution. |
| R6 | Hash salt rotates and item retirement is enforced | 1 | Salt rotation window is in CI; items retired after N appearances per rater. |
| R7 | Per-rater metrics include pass rate, 95% CI, per-slice, and confusion matrix | 1 | Dashboard shows all four; raw labels are stored, not just aggregates. |
| R8 | Drift contract wires numeric thresholds to specific actions (continue / retrain / pause / investigate) | 1 | `drift_contract.yaml`; each threshold maps to a named action and is enforced by the queueing code. |

**Passing bar:** 7 / 10.

Reviewer checklist:

- [ ] A rater is never adjudicating their own label (verified in code).
- [ ] Raw rater labels are never overwritten by the adjudicated verdict.
- [ ] Gold manifest has ≥ 2 signoffs per item, from distinct roles.
- [ ] Gold item IDs are hashed with a salt that rotates on schedule.
- [ ] Gold is not drawn from `examples.md`, training, or pilot pools.
- [ ] Gold injection rate matches the committed cadence (8% ± 1 pt, ≥ 15/week/rater, no stacking).
- [ ] Per-rater metrics include a per-slice breakdown; no rater is judged on aggregate alone.
- [ ] Each drift threshold is tied to a named action with an owner and an SLA.
- [ ] `guideline_gap` disagreements result in a committed patch and a task-version bump.

### 5. Common mistakes

- **Senior rater re-votes = "adjudication".** A senior rater replaying the labelling task on their own without a different role and without seeing all rater evidence is a louder vote, not a resolution. The adjudicator's job is to apply the rubric to the full evidence pack, and to classify the disagreement.
- **Overwriting raw labels with the adjudicated verdict.** Agreement statistics from [exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md) silently become unreproducible after adjudication. Record the adjudicated verdict alongside the raw labels, not instead of them.
- **Gold = "items everybody agreed on".** The easy items are also the biased items; a gold pool dominated by trivial cases cannot detect targeted drift. Mix in adjudicated `rater_error` and `ambiguous_item` cases per the construction protocol.
- **Single-approver gold.** The person who wrote the rubric is also the only one authorised to say what the rubric means. Two approvers in different roles is the floor.
- **Gold ID leakage.** A rater sees `item_id: q-00318` in production, memorises the label, and hits it again in gold. Hash salts rotated on schedule break this; without rotation, memorization inflates every pass rate.
- **Gold items never retire.** The same gold item re-presented to the same rater forever is a memorization test, not a calibration test. Retire after N appearances.
- **Gold injection rate too low to carry a CI.** 2% injection on a rater who labels 100 items a week is 2 gold items a week; the CI on a pass rate from n=2 is a decoration. 8% / 15 per week is a workable floor.
- **Position-stacked injections.** Gold items at positions 1 and 2 of every batch teach raters to perform for the first two items. Uniform within batch, never stacked.
- **Aggregate pass rate only.** A rater at 0.88 overall who is at 0.52 on code-topic items is missing a real slice. Per-slice is not optional.
- **Drift dashboard without actions.** A pretty line going down is not a control. Each threshold is wired to retrain / pause / investigate; a crossed threshold triggers the named action within the SLA.
- **Guideline gaps left unpatched.** A `guideline_gap` disagreement without a proposed patch becomes a recurring disagreement. The point of the classification is to feed the next pilot.
- **Treating a sudden pass-rate drop as "that rater got tired".** A single-rater single-slice drop with no guideline change is also the shape of ML02 data poisoning. Ruling the attack signal out is cheap; not checking is the cost.
- **No SLA on adjudication queue.** Items pile up; gold promotion stalls; the drift signal gets noisier; nobody notices for weeks. The SLA with a committed overdue action is what keeps the loop closed.

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MANAGE` and `MEASURE` functions together require continuous measurement of reliability with documented response thresholds; adjudication + rotation + drift contract are the operational form of that for a human-labelling pipeline.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML02 Data Poisoning** maps to a compromised gold item silently degrading every downstream evaluation; **ML08 Model Skewing** maps to undetected rater drift that biases the evaluation instrument.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` names the technique that exploits a leaked, unrotated, or single-signoff gold set.

<!-- Local exercise context: the injection rate (8%), the per-rater weekly floor (15), the maximum-non-gold spacing (40), the retirement threshold (5 appearances / rater), the salt rotation window (30 days), the readmission window (180 days), and the drift thresholds (0.85 continue, 0.70 pause) are illustrative defaults for a general-purpose pairwise task with mid-skilled raters. Recalibrate for your own label geometry, rater throughput, and cost ceiling before adopting. The upstream guideline is in [exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md); the IAA computation whose disagreements this exercise adjudicates is in [exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md); the labelling UX that injects gold items and enforces attention at runtime is in [exercise-04](../exercise-04-side-by-side-ux-with-attention-checks/SOLUTION.md). -->
