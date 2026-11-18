## exercise-01 — Absolute and Pairwise Rubric Design — Solution

### 1. Solution overview

The exercise asks the learner to design a **rubric and the two judge prompts that operationalize it**: an *absolute* prompt that asks a single LLM judge to score one response against the rubric, and a *pairwise* prompt that asks the same judge to pick between two responses on the same rubric. The rubric is the artifact; the two prompts are the operationalizations.

The reference answer has four deliverables:

1. A **rubric document** — a short, committed Markdown + YAML pair that fixes the criteria, the scale, the anchors for each level, and the tie rule. A judge prompt that does not reference a committed rubric is an opinion generator, not a measurement instrument.
2. An **absolute-scoring prompt template** — a parameterized judge prompt that returns a structured JSON verdict per response (per-criterion score, brief justification, overall score).
3. A **pairwise-comparison prompt template** — the same rubric expressed as "A vs B vs tie" with position-swap wiring (the control itself is scored in [exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md); this exercise only has to make the swap *possible*).
4. A **decision rule** — when to pick absolute vs pairwise, and how to report the headline number.

This maps to the NIST AI RMF `MEASURE` function, which requires measurements to be "tested, documented, and tied to an identified operational context" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). A rubric that is not committed and versioned fails that bar: any later change to the criteria or the anchors silently redefines the measurement. OWASP ML Top 10 **ML01 Input Manipulation** and **ML04 Membership Inference** are the attacker lenses — a judge whose rubric is not pinned is a judge whose verdict can be moved by rephrasing the inputs; a judge whose per-item verdict leaks its reasoning in free text leaks exactly the signal an attacker needs to craft rubric-aware outputs ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Craft Adversarial Data` and `LLM Prompt Injection` are the relevant tactics ([MITRE ATLAS](https://atlas.mitre.org/)).

### 2. Worked implementation

#### 2.1 Rubric document

Commit the rubric in two files: a human-readable `rubric.md` and a machine-readable `rubric.yaml`. The YAML is what the judge prompts interpolate; the Markdown is what reviewers and SMEs edit. Keep them in sync via a check in CI (section 3).

`rubric.md`:

```
# Helpfulness-and-Correctness rubric (v1.0)

Scope: single-turn assistant responses to a user question, in English, where
the gold-standard outcome is "the user got a correct, directly usable answer."

Criteria:
  1. Correctness      — Does the answer state true facts and solve the user's problem?
  2. Groundedness     — Are claims supported by the provided context (when context exists)?
  3. Instruction fit  — Does the response respect the user's explicit constraints?
  4. Clarity          — Is the response well-structured and free of filler?

Each criterion is scored 1–5 using the anchors in rubric.yaml. The overall
score is the arithmetic mean rounded to one decimal.

Ties in pairwise mode: a tie is required when |overall(A) - overall(B)| <= 0.4
OR when the judge cannot produce a justification that cites a concrete
difference. "I preferred A overall" is not a justification.
```

`rubric.yaml`:

```yaml
rubric_id: helpfulness_v1
version: "1.0"
scale:
  min: 1
  max: 5
criteria:
  - key: correctness
    weight: 1.0
    anchors:
      "1": "Answer is wrong or asserts a false claim as fact."
      "2": "Answer is partially wrong or omits the central fact."
      "3": "Answer is mostly correct but has a non-trivial error or hedge."
      "4": "Answer is correct with a minor imprecision."
      "5": "Answer is correct, complete, and directly usable."
  - key: groundedness
    weight: 1.0
    applies_when: "context_provided == true"
    anchors:
      "1": "Claims contradict the provided context."
      "2": "Claims are mostly unsupported by the provided context."
      "3": "Some claims are supported; others are not."
      "4": "Claims are supported but attribution is implicit."
      "5": "Every substantive claim is grounded in the provided context."
  - key: instruction_fit
    weight: 1.0
    anchors:
      "1": "Violates an explicit constraint (length, format, forbidden content)."
      "2": "Follows the gist but misses an explicit constraint."
      "3": "Follows explicit constraints with a minor deviation."
      "4": "Follows all explicit constraints."
      "5": "Follows all constraints and the obvious implicit ones."
  - key: clarity
    weight: 0.5
    anchors:
      "1": "Hard to parse; contradicts itself."
      "2": "Readable but noisy; significant filler."
      "3": "Readable; some filler."
      "4": "Clear and concise."
      "5": "Clear, concise, and well-structured for the question."
aggregation:
  method: weighted_mean
  round_to: 1
tie_rule:
  mode: pairwise
  threshold: 0.4
  require_justification: true
```

Three things this rubric does on purpose:

- **Anchors are observable, not aspirational.** "Correct and directly usable" is observable from the response; "well-reasoned" is not. Anchors that require the judge to guess intent produce unstable scores.
- **`applies_when` guards criteria that don't always apply.** Groundedness on an open-ended question with no provided context is not a meaningful criterion; marking it as inapplicable is better than forcing a fake score.
- **`clarity` has weight 0.5.** Clarity is the criterion where length bias enters most easily (see [exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md)). Halving its weight is a deliberate pre-commitment to not let a writing-style axis dominate a correctness-driven rubric.

#### 2.2 Absolute-scoring prompt template

Use a system prompt that pins the role, the rubric id, and the output schema; a user prompt that interpolates the item and the response.

```jinja
{# judge_absolute.prompt.j2 — rendered server-side; never pasted by hand #}
{# ---- system ---- #}
You are a strict evaluator applying the {{ rubric.rubric_id }} rubric
(version {{ rubric.version }}). You must score only on the committed
criteria and anchors. Do not invent new criteria. If a criterion does not
apply, return null for that criterion's score and explain why in one short
sentence. Return JSON only; no prose outside the JSON block.

Rubric (criteria, 1–5 anchors):
{% for c in rubric.criteria %}
- {{ c.key }} (weight {{ c.weight }}){% if c.applies_when %} — applies when: {{ c.applies_when }}{% endif %}
  {%- for level, text in c.anchors.items() %}
    {{ level }}: {{ text }}
  {%- endfor %}
{% endfor %}

Aggregation: weighted mean of per-criterion scores, rounded to 1 decimal.
If a criterion is null, drop it from the denominator.

Output schema (JSON):
{
  "rubric_id": "{{ rubric.rubric_id }}",
  "rubric_version": "{{ rubric.version }}",
  "per_criterion": {
    {% for c in rubric.criteria -%}
    "{{ c.key }}": {"score": 1|2|3|4|5|null, "evidence": "<= 240 chars"}{{ "," if not loop.last }}
    {% endfor %}
  },
  "overall": <float, 1 decimal, computed per the aggregation rule>,
  "flags": ["refusal" | "off_topic" | "safety_violation" | "unparseable"]
}

{# ---- user ---- #}
Question:
{{ item.question }}

{% if item.context %}
Provided context:
{{ item.context }}
{% endif %}

Candidate response:
{{ response.text }}
```

Non-obvious choices:

- **JSON schema is in the prompt.** Even with constrained decoding on the judge side, naming the schema in the prompt reduces retries and makes the judge's output auditable without a separate spec.
- **`evidence` is capped at 240 chars.** Long justifications invite rationalization and bleed the judge into writing-style preferences. A short evidence string forces a concrete citation.
- **`flags` is explicit.** Refusals, off-topic answers, and unparseable responses are not "score 1"; they are categorical outcomes that downstream analysis needs to separate. Collapsing them into the numeric scale loses information.
- **No chain-of-thought in the response.** The schema asks for the per-criterion `evidence`, not a reasoning trace. Free-form reasoning blocks are harder to validate, cost more tokens, and have no measurable benefit on rubric-anchored tasks that haven't been quantified in your own calibration study ([exercise-03](../exercise-03-judge-vs-human-calibration-study/SOLUTION.md) is where you measure this for your rubric).

#### 2.3 Pairwise-comparison prompt template

Same rubric, different output. The template takes `response_a` and `response_b` and returns a verdict. The caller decides which actual response goes into each slot and whether to swap.

```jinja
{# judge_pairwise.prompt.j2 #}
{# ---- system ---- #}
You are a strict evaluator applying the {{ rubric.rubric_id }} rubric
(version {{ rubric.version }}). Compare response A and response B against
the committed criteria below. You must return one of:
  - "A"   if A is clearly better on the weighted-mean rubric score,
  - "B"   if B is clearly better on the weighted-mean rubric score,
  - "tie" if |overall(A) - overall(B)| <= {{ rubric.tie_rule.threshold }}
          OR you cannot cite a concrete, rubric-anchored difference.

The tie option is not a last resort — it is the correct answer whenever the
responses are substantively equivalent on the rubric.

Rubric (criteria, 1–5 anchors):
{% for c in rubric.criteria %}
- {{ c.key }} (weight {{ c.weight }}){% if c.applies_when %} — applies when: {{ c.applies_when }}{% endif %}
  {%- for level, text in c.anchors.items() %}
    {{ level }}: {{ text }}
  {%- endfor %}
{% endfor %}

Output schema (JSON):
{
  "rubric_id": "{{ rubric.rubric_id }}",
  "rubric_version": "{{ rubric.version }}",
  "verdict": "A" | "B" | "tie",
  "per_criterion": {
    {% for c in rubric.criteria -%}
    "{{ c.key }}": {"winner": "A"|"B"|"tie", "evidence": "<= 240 chars"}{{ "," if not loop.last }}
    {% endfor %}
  },
  "flags": ["refusal_A" | "refusal_B" | "off_topic_A" | "off_topic_B" | "unparseable"]
}

{# ---- user ---- #}
Question:
{{ item.question }}

{% if item.context %}
Provided context:
{{ item.context }}
{% endif %}

Response A:
{{ response_a.text }}

Response B:
{{ response_b.text }}
```

Pairwise-specific choices:

- **`verdict` is categorical, not numeric.** Asking for a numeric preference strength on a pairwise comparison re-invents the absolute score through the back door and loses the benefit of the pairwise format.
- **Per-criterion winners.** A verdict without per-criterion winners is uninterpretable: you cannot tell whether "A" won because it was more correct or because it was longer. The per-criterion breakdown is what makes the length-bias control in [exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md) actionable.
- **The tie rule is restated in natural language.** The judge sees the same threshold the aggregation code uses. Any later change happens in the YAML and propagates to both.
- **Position-swap is a caller concern.** The template takes `response_a` and `response_b`; whether the actual model-A response goes into slot A or slot B, and whether both orderings are run, is wiring code — not something the judge should be asked to adjust for itself.

#### 2.4 Decision rule: absolute vs pairwise

Pick one as the headline measurement for a given eval set, and say so on the result card. Running both is fine for internal diagnostics; reporting both as the "score" is how incomparable numbers end up in the same table.

| Situation | Headline mode | Why |
|---|---|---|
| Regression gate on a single model against an **absolute quality bar** (e.g., "90% of answers must score ≥ 4.0") | Absolute | The gate is defined on an absolute scale; pairwise gives you a win rate against a comparator, not a quality floor. |
| Comparing two candidate models / two prompt variants on the same set | Pairwise (with order swap) | Pairwise agreement with humans is typically higher than absolute-score agreement at the same judge budget, because the judge only has to rank, not calibrate. Validate this in [exercise-03](../exercise-03-judge-vs-human-calibration-study/SOLUTION.md). |
| Leaderboard across N models | Pairwise, then rank via a Bradley-Terry fit | The arena construction is the subject of [exercise-04](../exercise-04-bradley-terry-arena-implementation/SOLUTION.md). |
| Tracking a model over time on a stable eval set | Absolute | Pairwise requires a fixed opponent; absolute doesn't, so you can keep comparing to the same rubric as the lineup changes. |
| Items where correctness is binary (math, code compiles, unit test passes) | Programmatic metric; not a judge | A judge on binary-correctness items wastes budget — use the deterministic check and keep the judge for subjective criteria. |

Rule of thumb: **absolute scoring measures a model against a standard; pairwise comparison measures a model against another model.** Confusing the two is the most common misread of judge output in production reviews.

#### 2.5 Reporting contract

Both modes write the same per-item record (one JSON line per judgement) so downstream analysis is uniform:

```json
{
  "run_id": "2026-11-17-helpfulness_v1-run003",
  "rubric_id": "helpfulness_v1",
  "rubric_version": "1.0",
  "mode": "pairwise",
  "item_id": "q-00318",
  "judge_model": "<org>/<model>@<revision>",
  "judge_decoding": {"temperature": 0.0, "top_p": 1.0, "seed": 1234},
  "order_seed": 1234,
  "slot_assignment": {"A": "candidate_x", "B": "candidate_y"},
  "verdict": "A",
  "per_criterion": {"correctness": {"winner": "A", "evidence": "..."}, "...": {}},
  "flags": [],
  "latency_ms": 1820,
  "cost_usd": 0.0041
}
```

The headline numbers on the result card:

- **Absolute:** mean overall score, 95% bootstrap CI (10 000 resamples, pinned seed), breakdown by criterion, and the fraction of items that tripped any `flag`.
- **Pairwise:** win-rate for each candidate with the position-swap collapse applied ([exercise-02](../exercise-02-position-and-length-bias-controls/SOLUTION.md)), tie rate, 95% CI.

### 3. Validation steps

1. **Rubric round-trip.** A script loads `rubric.yaml`, walks every criterion, and asserts that `rubric.md` lists the same criteria in the same order with the same anchors. A silent drift between the human doc and the YAML is how rubrics quietly change.
2. **Prompt render smoke test.** Render both templates against a fixture item + response(s) and parse the result as JSON. The parser must reject on any missing field; the smoke test fails the build when the schema drifts from the template.
3. **Anchor coverage test.** For every criterion, require that the judge was shown the anchor text for every level in the scale. If a level is missing, the judge is reading a truncated rubric and the scores on that criterion will be biased toward the levels it saw.
4. **Determinism check.** Same judge model, same seed, same inputs, two runs. Scores must be bit-identical. If they drift, something upstream is nondeterministic (temperature > 0, tool-use randomness, top-p sampling left on). Record it as a reproducibility bug and fix it before you report a headline.
5. **Tie-rule dry run.** Feed the pairwise prompt an item where `response_a == response_b`. The verdict must be `tie`; if the judge picks a side, your prompt isn't gating the tie rule (or the judge is ignoring it — move to a judge that follows it).
6. **Mode-mix guard.** On the result card / dashboard, the absolute score and the pairwise win-rate must be rendered in distinct units with a visible mode label. A reviewer who sees "0.68" without a mode label cannot tell whether that is a win rate or a 1–5 score / 5.
7. **Independence from decoded reasoning.** Rerun with the `evidence` fields stripped to empty strings and confirm the `overall` / `verdict` is the same. If the aggregation code secretly depends on the free-text justification, you have a silent dependency that will break on any template edit.

### 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a committed, auditable measurement instrument**, not a working prototype.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Rubric is committed as a machine-readable spec | 2 | `rubric.yaml` exists, is loaded by both templates, and is versioned. |
| R2 | Each criterion has concrete anchors for every scale level | 2 | No anchor is "well-reasoned" / "high quality" without an observable referent. |
| R3 | Absolute-mode template returns a validated JSON schema | 1 | Schema is in the prompt; parser rejects missing fields; smoke test runs in CI. |
| R4 | Pairwise-mode template supports position-swap at the call site | 1 | Template takes `response_a` / `response_b` with no built-in assumption of which is "ours"; caller controls the swap. |
| R5 | Tie rule is explicit and enforced on both the model side and the aggregation side | 1 | Threshold lives in `rubric.yaml`; both the prompt text and the aggregation code reference it. |
| R6 | Per-item record carries judge model, seed, rubric version, slot assignment | 1 | A reviewer can replay any single judgement from the record alone. |
| R7 | Decision rule for absolute vs pairwise is committed | 1 | A short doc or matrix in the repo picks the headline mode for each eval set; result cards label the mode. |
| R8 | Clarity criterion is explicitly down-weighted or justified | 1 | Either `clarity` has weight < 1, or the rubric doc explains why equal weight is appropriate for this domain. |

**Passing bar:** 7 / 10. Below that, the rubric is a prompt-engineering exercise, not an instrument.

Reviewer checklist:

- [ ] Every anchor is an observable statement, not an aspirational one.
- [ ] `rubric.yaml` and `rubric.md` agree on criteria, scale, and anchors (verified in CI).
- [ ] Judge prompts only reference committed criteria; no criterion is invented inline.
- [ ] Pairwise template is symmetric in `response_a` / `response_b` — no hidden preference for either slot.
- [ ] Per-item record has enough fields to replay the judgement.
- [ ] Result card labels the mode and the rubric version.
- [ ] The tie rule has been exercised with a known-tie fixture.

### 5. Common mistakes

- **Rubric lives in the prompt, not a file.** The rubric text is pasted into the prompt as a string literal. Any later change silently reweights every historical comparison. Commit the YAML and interpolate.
- **Anchors describe the judge's feelings instead of the response.** "The answer feels confident" is a judge-state anchor; "the answer asserts X as fact" is a response-state anchor. Only the second is auditable.
- **Numeric preference strength on pairwise.** Asking "how much better is A, 1–10?" re-creates absolute scoring inside a pairwise call and loses the whole reason to use pairwise.
- **No tie option.** A forced-choice pairwise prompt converts "no meaningful difference" into a coin flip and inflates the win-rate variance by a wide margin. Always give `tie` as an option and enforce the threshold.
- **Chain-of-thought spilled into the verdict.** When the judge is allowed to write arbitrary reasoning before the verdict, it frequently talks itself into a side and the per-criterion evidence becomes a post-hoc rationalization. Cap evidence length; keep the verdict structured.
- **Reporting both modes as "the score."** A win rate and an absolute mean are not the same measurement. Picking one for the headline and surfacing the other as a diagnostic is the right default.
- **Swapping in a stronger judge without re-pinning the rubric version.** A judge model upgrade with no `rubric_version` bump makes old and new runs look comparable when they aren't. Bump the version whenever the judge model or the rubric text changes.
- **Treating `flags` as score zero.** A refusal is categorically different from a bad answer. Breaking them out preserves the signal; collapsing them hides it.

### 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires metrics to be tested, documented, and tied to an operational context; the committed rubric + schema'd judge prompts are the operationalization of that for LLM-as-judge.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML01 Input Manipulation** motivates pinning the rubric and the judge decoding; **ML04 Membership Inference** motivates keeping free-text justifications short and structured.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` and `LLM Prompt Injection` are the techniques that a non-pinned, free-form judge prompt makes cheaper for an attacker.

<!-- Local exercise context: the `helpfulness_v1` rubric, the item id `q-00318`, and the specific weights / thresholds in this solution are illustrative. Real rubrics must be built from domain data and calibrated with the study in exercise-03 before any headline number is reported. -->
