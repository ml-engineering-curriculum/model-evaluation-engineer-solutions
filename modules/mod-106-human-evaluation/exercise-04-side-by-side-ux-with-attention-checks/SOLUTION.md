## exercise-04 — Side-by-Side UX with Attention Checks and Bot Detection — Solution

### 1. Solution overview

The upstream guideline ([exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md)), the agreement analysis ([exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md)), and the adjudication / gold rotation ([exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md)) are only as reliable as the UX that produces the raw labels. This exercise is about the **labelling surface**: the side-by-side (SxS) UI, the attention checks that guarantee raters are actually reading the item, and the bot / fatigue detectors that catch labels produced by a script, a shared account, or a tired human on autopilot.

The reference answer has five deliverables:

1. A **SxS UI specification** — a committed description of what the rater sees, in what order, with what controls, and what metadata the UI records per label. The UX is a measurement instrument; a change to the layout changes the labels.
2. An **attention-check inventory** — a committed catalogue of attention-check types (gold injections, instructed-response items, consistency pairs, honeypot flags) with the rate at which each is injected and the pass criteria.
3. A **bot / automation detector** — a small policy that combines timing, mouse/keyboard interaction, response-pattern entropy, and infrastructure signals (IP reputation, UA fingerprint, headless-browser markers) into a per-session risk score with documented thresholds.
4. A **blinding, randomization, and anti-anchoring design** — position swap, candidate identity blinding, criteria presentation order, flag-button placement, and the record of per-rater randomization seeds that feed into the agreement computations.
5. A **rater response contract** — the numeric thresholds that fire pause / retrain / investigate when the UX-produced signals cross a line, mirrored against the drift contract from [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md) so the same rater cannot slide past both controls.

This maps to the NIST AI RMF `MEASURE` and `MANAGE` functions, which require measurement instruments to be documented, operationalized, and monitored for reliability drift ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens covers two OWASP ML Top 10 entries — **ML02 Data Poisoning** (bot / scripted / incentive-driven raters that inject biased labels) and **ML08 Model Skewing** (fatigue, UI priming, position bias that produce a systematic lean in the labels) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Craft Adversarial Data` describes the attacker who writes to the labelling surface rather than to the model ([MITRE ATLAS](https://atlas.mitre.org/)).

### 2. Worked implementation

The running example remains the pairwise helpfulness task from [exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md), with 3 raters per item and label set `{"1", "2", "tie"}`. The spec below is the committed contract between the UI and the rest of the labelling pipeline; it is what the backend validates on every submission.

#### 2.1 SxS UI specification

Commit the UX contract as `ui/sxs_spec.yaml`:

```yaml
# ui/sxs_spec.yaml
task_id: helpfulness_pairwise
task_version: "1.0"

layout:
  columns: 2                                   # two responses, side by side
  column_labels: ["Response 1", "Response 2"]  # positions, never model names
  column_order_per_item: "randomized_per_rater"
  response_scroll_sync: false                  # scroll each column independently
  question_panel: "always_visible_above_responses"
  rubric_panel: "collapsible_right_sidebar; collapsed_by_default"
  worked_examples_link: "visible; opens in a separate tab (never a modal)"

controls:
  verdict_buttons:
    - {id: "verdict_1",   label: "Response 1 is better", shortcut: "1"}
    - {id: "verdict_2",   label: "Response 2 is better", shortcut: "2"}
    - {id: "verdict_tie", label: "Tie",                   shortcut: "t"}
  per_criterion_pickers:
    presentation_order: "randomized_per_item"
    fields: ["correctness", "groundedness", "instruction_fit", "clarity"]
  evidence_field:
    max_chars: 240
    required_on_submit: true
  flag_menu:
    always_available: true
    buttons: ["refusal", "off_topic", "unanswerable", "harmful_content"]
    confirmation_required: true

submission:
  can_retract_before_next_item: false          # ship on submit; no post-hoc edits
  minimum_dwell_seconds: 8                     # see attention checks; items under budget surface a warning
  stuck_warning_seconds: 180                   # surfaces guidance but does not force-submit

telemetry_recorded_per_label:
  - item_id_hashed
  - task_version
  - rater_id_anonymised
  - column_order_seed
  - criterion_order_seed
  - verdict
  - per_criterion_choices
  - evidence
  - flags
  - dwell_ms_total
  - dwell_ms_each_response_column
  - scroll_depth_each_column
  - keyboard_vs_pointer_submits_ratio_window
  - user_agent_fingerprint_hash
  - submitted_at (server)

required_blinding:
  - "column position is independent of model identity"
  - "no model name, model family, or system prompt leaks into the DOM or the page source"
  - "no filename / url hint reveals response origin"
  - "network tab shows a single uniform response-fetch endpoint"
```

Three things the spec does on purpose:

- **Positions have fixed labels, "Response 1" / "Response 2", never model names.** Any production system that prints "Claude vs GPT" above the columns has just erased blinding; the spec forbids it.
- **Column order randomises per rater (and ideally per impression).** Position bias is otherwise confounded with every slice-level finding. The order seed is recorded so the agreement module can reconstruct the layout each rater saw.
- **Rubric panel is collapsed by default, worked examples open in a separate tab.** A rater who is holding the rubric and examples open while scanning both responses makes better decisions; forcing them to click into modals breaks their reading flow and silently increases dwell-time variance.
- **`can_retract_before_next_item: false`.** Retraction is a classic backdoor to selection bias — a rater sees the next item, decides the previous one was wrong, revises. The audit trail is lost and the UX is no longer a measurement instrument. Correctness-after-the-fact flows through the adjudication path in [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md), not through UI retraction.

A sketch of the SxS layout:

```
+--------------------------------------------------------------------+
|  Question                                                          |
|  "Explain how TCP achieves reliable delivery in one sentence."     |
+--------------------------------+-----------------------------------+
|  Response 1                    |  Response 2                       |
|  [scrollable]                  |  [scrollable]                     |
|                                |                                   |
|                                |                                   |
+--------------------------------+-----------------------------------+
|  [ R1 better ]   [ Tie ]   [ R2 better ]   [ Flag ▾ ]              |
|  Per-criterion:  correctness [R1|R2|tie]  groundedness [...]       |
|                  instruction_fit [...]    clarity [...]            |
|  Evidence: _________________________________________________       |
|            [submit]                                                |
+--------------------------------------------------------------------+
```

#### 2.2 Attention-check inventory

Commit the catalogue as `ui/attention_checks.yaml`:

```yaml
# ui/attention_checks.yaml
types:
  - name: gold_injection
    source: "gold pool from exercise-03"
    injection_rate_per_rater: 0.08
    detection: "verdict != gold_label"
    on_fail: "feeds per-rater drift contract (exercise-03)"
    rationale: "measures rubric adherence under realistic conditions."

  - name: instructed_response
    description: "a minority of items contains an embedded instruction the rater must obey (e.g., in the question: 'For this calibration item, pick \"tie\" regardless of responses.')"
    injection_rate_per_rater: 0.01
    detection: "verdict != the instructed response"
    on_fail:
      first_fail_in_window: "surface a one-time reminder, no action"
      second_fail_in_window: "flag session for review; exclude session's non-gold labels from the eligible pool"
    rationale: "catches raters who are skimming for pattern rather than reading the item."

  - name: consistency_pair
    description: "two items in the same batch are near-duplicates with roles swapped. A consistent rater produces logically consistent verdicts (if verdict('A,B') == '1', verdict('B,A') must be '2'); allowed deviation is a small tolerance for truly tied items."
    injection_rate_per_rater: 0.02
    detection: "inconsistent verdict across the swapped pair"
    on_fail: "counts toward the session's inconsistency score; three in a week surfaces for review"
    rationale: "measures position bias at the per-rater level; complements the pool-wide bias check in upstream analysis."

  - name: honeypot_flag
    description: "items that should unambiguously trigger a specific flag (e.g., one response that is clearly off-topic). Raters who return a verdict instead of a flag have missed the required flag."
    injection_rate_per_rater: 0.01
    detection: "verdict is returned when the expected output is flag=<x>"
    on_fail: "same ladder as instructed_response"
    rationale: "catches raters who always rank, never flag."

enforcement:
  windowing: "rolling 100-item window per rater"
  logging: "every check outcome is recorded alongside the label record for audit"
  separation_of_duties: "attention-check items are maintained by a role distinct from raters; see exercise-03 signoff rules"

non_duplication:
  - "attention-check items are not drawn from the examples pack (exercise-01)"
  - "attention-check items are not drawn from the production pool"
  - "attention-check items are not drawn from non-check gold items without a role-change audit"
```

Why these four, in this combination:

- **Gold injection measures correctness against a known reference.** It is the strongest per-rater calibration signal and is already the backbone of [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md).
- **Instructed-response items measure attention independent of correctness.** A rater who is skim-reading will miss the instruction regardless of their rubric skill.
- **Consistency pairs measure position bias at the individual-rater level.** A rater who consistently picks the response in column 1 fails the pair test even if their rubric-level verdicts look reasonable.
- **Honeypot flags measure flag-vs-rank behavior.** Raters who never use the flag menu aren't using the taxonomy, which collapses important categorical outcomes into score-zero verdicts (see common mistakes).

Injection rates sum to 12% of a rater's items being some form of attention check. That is high enough to carry a per-rater signal and low enough not to dominate the labelling cost.

#### 2.3 Bot and automation detector

Commit the policy as `ui/bot_detector.yaml`:

```yaml
# ui/bot_detector.yaml
score_components:
  - name: dwell_too_short
    signal: "median dwell_ms_total over last 20 items"
    threshold: "median < 2000 ms"
    weight: 3
    rationale: "A human reading two responses and a rubric cannot produce a median dwell below 2 s."

  - name: dwell_too_uniform
    signal: "coefficient_of_variation of dwell_ms_total over last 20 items"
    threshold: "cv < 0.08"
    weight: 2
    rationale: "Even a focused human has natural variance; a bot clock does not."

  - name: entropy_of_verdicts
    signal: "Shannon entropy over verdict + per_criterion space in the last 50 items"
    threshold: "entropy < 60% of pool median"
    weight: 2
    rationale: "A rater who always picks '1' or always picks 'tie' has a degenerate output distribution."

  - name: no_pointer_events
    signal: "fraction of submits with zero pointer events in the last 20 items"
    threshold: "> 0.75"
    weight: 2
    rationale: "Keyboard-only is legitimate; zero-interaction is not."

  - name: no_scroll_on_long_responses
    signal: "fraction of items where scroll_depth_each_column < 0.30 while response length > viewport"
    threshold: "> 0.50"
    weight: 2
    rationale: "A rater who never scrolls a response that doesn't fit cannot be reading it."

  - name: headless_browser_marker
    signal: "user_agent + navigator.webdriver + missing plugins / canvas fingerprint anomalies"
    threshold: "any strong marker present"
    weight: 3
    rationale: "Unambiguous automation signal; does not require the other checks to trigger a hold."

  - name: session_concurrency
    signal: "same rater_id active in >1 session within a 30 s window"
    threshold: "> 1"
    weight: 3
    rationale: "A shared account is not a single rater; agreement statistics assume per-rater independence."

  - name: ip_reputation
    signal: "IP flagged as datacenter / known-VPN / known-fraud in the identity provider feed"
    threshold: "flagged"
    weight: 1
    rationale: "Datacenter IP alone is not disqualifying for legitimate crowd pools; it compounds with other markers."

aggregation:
  score: "sum(weight for each triggered component)"
  bands:
    allow:          "score == 0"
    warn:           "1 <= score <= 3"     # log, surface to supervisor; no rater-visible change
    throttle:       "4 <= score <= 6"     # pause rater's new-item assignment; drain in-flight
    hold:           "score >= 7"          # lock session; mark non-gold labels ineligible for pool
  concurrency_or_headless_shortcut:
    hold_regardless: true                 # either alone forces hold

review:
  owner: "task_owner + rater_ops"
  SLA_hours_for_hold_review: 24
  false_positive_appeal: "documented; rater receives a one-line reason for every hold"

logging:
  every_decision_recorded: true
  replay_window_days: 90
```

Non-obvious choices:

- **No single signal auto-bans.** The weights are tuned so that a legitimate rater using keyboard shortcuts and typing quickly will not trip the `hold` band on activity alone; it takes a combination of signals to cross the line. The two shortcuts (headless marker, session concurrency) are the exceptions because they are categorically different from "fast rater."
- **Entropy over the verdict+criteria space, not just verdicts.** A rater who always clicks `verdict=1` but varies per-criterion might be legitimately biased on an easy batch; a rater who stamps the exact same per-criterion pattern across 50 items is almost certainly not reading.
- **`dwell_too_uniform` is a gate on the second moment, not the mean.** Humans produce variance; bots produce clocks.
- **Zero-pointer-events is a signal, not a disqualification.** Power users using the keyboard shortcuts legitimately submit without pointer events on many items; the rule is "more than 75% of the last 20 items" — that is what separates a fast rater from a scripted one.
- **Hold decisions are reviewed within 24 h with a one-line reason.** A rater held with no explanation loses trust and also loses the ability to improve; the appeal path is part of the control, not an afterthought.

A minimal scoring function:

```python
# ui/bot_detector.py
from collections import Counter
import math


def shannon_entropy(labels):
    c = Counter(labels)
    n = sum(c.values())
    if n == 0:
        return 0.0
    return -sum((v / n) * math.log2(v / n) for v in c.values() if v > 0)


def score_session(signals, policy):
    """signals: dict of named observations. policy: parsed bot_detector.yaml.
    Returns (score, triggered, band)."""
    score = 0
    triggered = []
    shortcut = False
    for comp in policy["score_components"]:
        name = comp["name"]
        if name not in signals:
            continue
        if _triggered(name, signals[name], comp["threshold"]):
            score += comp["weight"]
            triggered.append(name)
            if name in {"headless_browser_marker", "session_concurrency"}:
                shortcut = True
    band = _band(score, policy["aggregation"]["bands"])
    if shortcut and policy["aggregation"].get("concurrency_or_headless_shortcut", {}).get("hold_regardless"):
        band = "hold"
    return score, triggered, band
```

Keep the scoring deterministic given the policy and the signals. A detector that depends on model-side randomness is one that cannot be audited after the fact.

#### 2.4 Blinding, randomization, and anti-anchoring

Collected across several knobs that must all be enforced at the UX layer (committing them to `ui/blinding.yaml` is the easiest single-source):

```yaml
# ui/blinding.yaml
candidate_identity:
  columns_show: "Response 1 / Response 2 only"
  dom_sanitization:
    strip:
      - "model name attributes, system prompt, reasoning traces, assistant metadata"
      - "filename or url strings that would reveal candidate"
    normalize:
      - "whitespace / trailing newlines / markdown fencing across both responses before render"
  network:
    single_endpoint: "GET /items/:hash"
    response_body: "returns Response 1 / Response 2 keyed by position, never by model_id"

position_randomization:
  column_order_seed_per_rater: true
  column_order_seed_per_item: true
  record: "seed stored alongside label record"

criterion_order:
  presentation_order_seed_per_item: true
  record: "seed stored alongside label record"

anti_anchoring:
  first_item_never_gold: "first 2 items per session are warm-up and never scored for gold"
  no_adjacent_duplicates: "two near-identical items cannot appear back-to-back (consistency pairs excepted; see attention_checks.yaml)"
  no_rater_names_in_ui: "rater display name is a per-session pseudonym; even the rater's self-view does not show their legal name"

reporting_from_seeds:
  position_bias_estimate: "upstream agreement module (exercise-02) uses the stored column_order_seed to decompose per-rater verdicts into position-independent and position-dependent components"
```

The design rules this encodes:

- **The DOM is a measurement surface.** `strip` and `normalize` rules close the leak paths where a rater could tell Response 1 from Response 2 by whitespace / markdown habits / token signatures. A rater who correctly identifies the model has done useful work on the wrong question.
- **The single-endpoint rule removes network-layer leakage.** If Response 1 comes from `/anthropic/v1/...` and Response 2 comes from `/openai/v1/...`, the network tab has stamped the identity on the labels.
- **Position and criterion seeds are stored on the label.** The downstream agreement module from [exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md) reads these seeds to estimate position bias per rater and per pool; a deployment that discards them is choosing not to measure its own UX.
- **First two items of a session are never gold.** Fresh raters open the task and look around; scoring the first impressions against gold produces false-negative drift signals that are really just first-item warmup.

#### 2.5 Rater response contract

The UX produces signals ([section 2.3](#23-bot-and-automation-detector), [section 2.2](#22-attention-check-inventory)); the response contract wires them to actions, mirrored and composed against the drift contract from [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md). Commit as `ui/response_contract.yaml`:

```yaml
# ui/response_contract.yaml
per_session:
  bot_detector_band: hold
    action:
      - "lock session immediately"
      - "mark non-gold labels from the session as ineligible until review"
      - "notify rater with a one-line reason"
      - "owner reviews within 24 h"
  bot_detector_band: throttle
    action:
      - "pause assignment of new non-gold items"
      - "drain in-flight items"
      - "surface to supervisor; may release after one-line write-up"

per_rater_rolling_100:
  instructed_response_fail: ">= 2 in window"
    action: "escalate per attention_checks.yaml"
  honeypot_flag_fail: ">= 2 in window"
    action: "re-deliver the flag-usage section of guidelines (exercise-01)"
  consistency_pair_fail: ">= 3 in window"
    action: "surface per-rater position-bias dashboard; retrain on blinding and tie rule"
  gold_pass_rate: "see exercise-03 drift contract"

pool_wide:
  bot_hold_rate_week: "> 0.5% of sessions"
    action: "treat as ML02 (data poisoning) signal; investigate before accepting any new labels from affected pool"
  mean_dwell_drop_week_over_week: "> 25%"
    action: "pause new assignments to pool; investigate for incentive structure change (rate-per-item too aggressive, task fatigue)"
```

The contract is the combination that matters. A rater with a declining gold pass rate alone is retrained under [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md). A rater with a stable gold pass rate but a creeping bot-detector score is retrained here. A rater who clears both independently but has consistency-pair failures is retrained here too. Three controls on three different signals, composed.

### 3. Validation steps

1. **DOM blinding audit.** Open the staging labelling UI with developer tools. Inspect the DOM, the initial HTML payload, and the network responses for any string matching a model name, system-prompt fragment, or candidate id. CI runs a headless-browser check for the same strings on a fixed item set; a match fails the build.
2. **Column-order replay.** Given a rater's historical labels and the stored `column_order_seed` per item, re-render the UI and confirm that Response 1 / Response 2 would have been shown in the same order. If replay diverges, the seed storage is broken and the agreement module cannot decompose position bias.
3. **Attention-check injection rate audit.** Replay a week of assignments and confirm that each attention-check type hit the committed rate per rater (±1 pt), without being concentrated at the start or end of sessions.
4. **Honeypot label ground truth.** For every honeypot item, the expected flag is in the manifest; CI confirms the manifest hasn't drifted from the item text. A honeypot whose "correct" flag no longer matches the content is a false-positive factory.
5. **Bot-detector unit tests.** `tests/test_bot_detector.py` includes fixtures for: a legitimate fast rater (keyboard shortcuts, dwell variance intact) landing in `allow`; a uniform-dwell scripted session landing in `throttle`; a headless-browser marker alone landing in `hold`; two concurrent sessions for one `rater_id` landing in `hold`. Thresholds drifting without a conscious edit fail the tests.
6. **Shortcut rule enforcement.** Specifically test that `headless_browser_marker` or `session_concurrency` alone forces `hold` regardless of other signals.
7. **Retraction lockout.** Attempt to retract a submitted label via the backend API with a replayed session cookie. The backend refuses; the test asserts the refusal is logged. A UI with a hidden retraction path invalidates the audit trail.
8. **Warmup non-scoring.** For 100 fresh sessions, confirm that none of the first two items per session is a gold item. A warmup rule that is not enforced produces apparent-drift that is only first-impression noise.
9. **Seed persistence.** For every label record, `column_order_seed` and `criterion_order_seed` are present and non-null. CI fails on any missing value in the last 7 days of records.
10. **Reason-on-hold check.** Every `hold` decision in the audit log has a non-empty one-line reason. A `hold` with no reason is an un-appealable action and breaks the rater's trust loop.
11. **End-to-end blinding spot check.** Monthly, a rater-ops reviewer tries to identify the model behind Response 1 vs Response 2 on 50 items chosen from the production stream. A detection rate materially above chance is a blinding failure and the UI change that caused it is rolled back before the next labelling window.

### 4. Rubric or review checklist

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | SxS UI is committed as a spec, not just code | 2 | `ui/sxs_spec.yaml` loaded by both UI and backend; label submissions rejected when fields are missing. |
| R2 | Position and criterion order randomize per rater / per item; seeds are stored | 1 | `column_order_seed` and `criterion_order_seed` on every record; replay test passes. |
| R3 | Candidate identity is blinded in the DOM, network, and metadata | 2 | CI blinding audit catches model-name leaks; single-endpoint rule enforced. |
| R4 | Attention-check inventory is committed with rates, pass criteria, on-fail actions | 1 | `ui/attention_checks.yaml` with four types; injection-rate audit passes. |
| R5 | Bot / automation detector combines multiple signals with explicit weights and bands | 1 | `ui/bot_detector.yaml`; shortcut rules forced; unit-test fixtures pass. |
| R6 | First-session warmup items are never scored for gold | 1 | Spec enforced; warmup items absent from gold pass-rate inputs. |
| R7 | Rater response contract wires numeric thresholds to specific actions | 1 | `ui/response_contract.yaml`; per-session, per-rater, pool-wide actions named with owners and SLAs. |
| R8 | Labels cannot be retracted after submit; corrections flow through adjudication | 1 | Backend enforces; retraction attempt is denied and logged. |

**Passing bar:** 7 / 10.

Reviewer checklist:

- [ ] No model name, system prompt, or candidate id appears anywhere a rater can see.
- [ ] Column labels are "Response 1 / Response 2" everywhere; model names are nowhere.
- [ ] Column order randomizes per rater / per item; the seed is on every label record.
- [ ] Rubric panel and worked examples are accessible without covering the responses.
- [ ] Evidence string is required on submit; max 240 chars is enforced server-side.
- [ ] Flag menu is always visible; confirmation is required.
- [ ] Attention checks hit the committed injection rates and are distributed through the session, not stacked.
- [ ] Bot detector produces an auditable score with a reason log; shortcut rules force `hold` on their own.
- [ ] The first two items of each session are warmup and are not counted toward gold pass rate.
- [ ] Submitted labels cannot be retracted via UI or backend; corrections go through adjudication.
- [ ] Every `hold` decision has a one-line reason and a 24 h review SLA.

### 5. Common mistakes

- **Model names above the columns.** "Claude vs GPT" above Response 1 / Response 2 erases blinding; every subsequent agreement number is confounded with brand loyalty.
- **Column order fixed per batch.** If every item in a batch shows Response 1 on the left and Response 2 on the right, position bias loads directly onto the "left is better" axis and the pool-wide bias check from [exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md) blows up. Randomize per item.
- **Retraction UI with an "I changed my mind" button.** Raters see the next item, change their mind on the previous one, revise. The audit trail is lost; corrections should flow through [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md).
- **Rubric and examples open as modals that cover the responses.** Raters stop opening them and label from memory. Side-panel the rubric; open examples in a separate tab.
- **Attention checks stacked at session start.** Raters learn the pattern — concentrate attention, then skim. Spread checks through the session; keep the warmup non-scoring.
- **Honeypot flags marked in the manifest but not re-validated when the item text is edited.** Someone fixes a typo in the honeypot item; the "expected" flag no longer matches the text. Every rater fails; the dashboard lights up. Validate manifest consistency in CI.
- **Bot detector that fires on dwell alone.** Fast legitimate raters are banned; slow bots that pace their submissions pass. Combine signals with weights.
- **Headless-browser marker treated the same as "datacenter IP".** They are not comparable. A headless marker is near-definitive; a datacenter IP alone is weak. The shortcut rules reflect that asymmetry.
- **No audit log on hold / throttle decisions.** Raters are held without a reason; trust collapses; the appeal path is not usable. One line per hold is the floor.
- **Session concurrency ignored.** Multiple browsers open under the same rater_id is a shared account. Agreement statistics assume per-rater independence; a shared account destroys that assumption without anyone noticing.
- **First-session items scored for gold.** A rater opens the task, adjusts to the UI, misreads the first item. The "gold drop" is warmup noise, not drift. Warmup does not count.
- **Verdict + per-criterion in a single collapsed JSON blob with no separate fields.** Downstream analysis — the per-criterion breakdown in [exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md), the position-bias decomposition that depends on the stored seeds — cannot be done without the fields being separately stored.
- **Shiny UI with no telemetry.** A beautiful labelling app that records only `verdict` on submit is not a measurement instrument. The telemetry list in `sxs_spec.yaml` is what makes every downstream analysis possible.

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires measurement instruments to be documented and reliable under operational conditions; the `MANAGE` function requires continuous monitoring with documented responses. The SxS spec + attention checks + bot detector + response contract are the operational form of both for a labelling surface.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML02 Data Poisoning** maps to scripted, incentive-driven, or shared-account raters injecting biased labels; **ML08 Model Skewing** maps to position / fatigue / anchoring biases that produce a systematic lean the agreement machinery alone would not surface.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` is the technique that writes directly to the labelling surface rather than to the model; the UX controls described here are the narrowest place to intercept it.

<!-- Local exercise context: the attention-check injection rates (gold 8%, instructed-response 1%, consistency-pair 2%, honeypot-flag 1%), the bot-detector weights and thresholds (dwell < 2 s, cv < 0.08, entropy < 60% of pool median, no-pointer-events > 75%, no-scroll > 50%, concurrency / headless as shortcuts), the warmup window (first 2 items), the SLA on hold review (24 h), and the dwell-drop pool trigger (25% week-over-week) are illustrative defaults for a general-purpose pairwise task. Recalibrate for your own rater pool, label geometry, and cost structure before adopting. The upstream guideline is in [exercise-01](../exercise-01-annotation-guidelines-and-pilot/SOLUTION.md); the agreement module whose stored seeds this UX produces is in [exercise-02](../exercise-02-iaa-computation-and-disagreement-analysis/SOLUTION.md); the adjudication and gold-set rotation that this UX injects into is in [exercise-03](../exercise-03-adjudication-and-gold-set-rotation/SOLUTION.md). -->
