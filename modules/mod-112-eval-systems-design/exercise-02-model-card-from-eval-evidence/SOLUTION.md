# exercise-02 — Model Card Composed from Eval Evidence — Solution

## 1. Solution overview

A model card is the document that sits between "the model exists" and "someone downstream decided to use it." Done well it is the **release artifact that links every claim back to a numbered piece of eval evidence**, auditable by anyone who reads the repo. Done badly it is a marketing brief: adjectives without numbers, screenshots without CIs, and a "limitations" section that no risk reviewer can act on. The job of this exercise is to compose a model card whose every section is **grounded in an eval artifact with a sha** — the card is not the primary document, the eval evidence is; the card is a view over it.

The design hinges on four non-negotiables:

- **Every claim cites an eval artifact by sha, not by prose.** "Performs well on Spanish" is not a claim; "achieves 0.75 first-turn resolution on `intent:billing, lang:es`, 95% bootstrap CI [0.74, 0.76], evidence sha256:7f3a... in eval-run `rc.2`" is a claim. A reviewer who wants to doubt the claim opens the run artifact and reads it.
- **Intended use and out-of-scope use are both named.** A card that lists only intended use is a sales doc; a card that names three out-of-scope uses with named failure modes is a risk doc. The out-of-scope list is the harder half; it is also the half with legal weight.
- **Limitations map to the evidence that exposed them.** "May underperform on code-mixed Spanish-English" is a claim with a receipt; the receipt is the slice `lang:es-en-codemixed` and its measured score. Limitations invented without eval data are speculation and read as filler.
- **The card is versioned with the model and republished on every release.** A card without a version is a card frozen at launch; one card for "v3" that silently covers v3.0 through v3.4 is how the "what did v3.2 actually claim?" question becomes unanswerable. The card is a registry artifact (see [mod-111 exercise-01](../../mod-111-eval-platform-engineering/exercise-01-versioned-registry-design/SOLUTION.md)) with its own sha, and its sha is recorded alongside the model's sha in the release manifest.

The reference answer has five deliverables:

1. A **worked model card** (`MODEL_CARD.md`) for a specific model (here: a billing-chat support assistant, v3.4.0) with every claim citing an eval sha.
2. An **evidence map** (`model_card_evidence.yml`) — the machine-readable, section-by-section mapping from card claim → eval-run sha → dataset sha → metric sha.
3. A **section schema** (`schemas/model_card.schema.json`) that every published card validates against; used by the card-publish CI step to reject cards with missing required sections or unresolved evidence shas.
4. A **changelog policy** (`docs/card-changelog.md`) that names what counts as a card revision (new section, new claim, revised limitation) vs. a model revision (new sha).
5. A **publish-and-review gate** (`ci/publish_model_card.py`) that runs the schema check, verifies every `evidence_sha256` resolves in the registry, posts the card as a registry artifact (`model_cards/<model_id>@v3.4.0`), and requests sign-off from the owner teams named in the card.

This follows the structure of the Google Model Cards Toolkit and the NIST AI RMF `MEASURE` and `MANAGE` functions: `MEASURE` asks that "performance be documented per context and subpopulation" — the slice-level numbers with CIs are the documentation; `MANAGE` asks that "deployment decisions be traceable to the evidence that supported them" — the evidence map is the traceability ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10: **ML09 Output Integrity Attacks** is why every claim must cite an evidence sha — a card whose numbers can be edited in-place is itself an integrity vector; **ML08 Model Skewing** is why the demographic/language breakdowns must be in the card, not summarized into a single accuracy number ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0005 Deliver Model via Publicly Available Service` and `AML.T0006 Active Scanning` frame the card as the interface adversaries read before they attack; what you disclose is a defense-and-threat trade-off the card must consciously make ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation — model card

### 2.1 The worked product

The same billing-chat support assistant from [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md). The gate run in exercise-01 produced evidence; this exercise composes a card from that evidence. The two documents are not independent: the card's numbers cite the gate-run shas.

### 2.2 Model card

```markdown
# Model Card — support-assistant@v3.4.0

Card version: v1.0 (2026-11-27)
Card sha256: <computed at publish>
Model sha256: models/support-assistant@sha256:91de4b2a...
Model owner: support-product@team
Card owner:  model-eval@team
Evidence map: model_card_evidence.yml (see §9)

---

## 1. Model details

- **Name.** support-assistant
- **Version.** 3.4.0 (release candidate rc.2 promoted after remediation; see §9 for gate history)
- **Type.** Retrieval-augmented chat assistant for a billing-and-subscriptions product.
- **Backbone.** Internal fine-tune of `llm-base@v7.1` (see internal registry).
- **Owners.** support-product@team (product), model-eval@team (eval), ml-responsibility@team (safety).
- **Release date.** 2026-11-27.
- **License.** Internal use only; no external redistribution.

## 2. Intended use

- **Primary.** First-turn triage of customer billing and subscription questions
  for English, Spanish, and German speakers, with a human-escalation path for
  cases the assistant flags as unresolved.
- **Secondary (monitored, not gated).** Tier-free users submitting account-state
  questions (balance, last charge, next charge). Monitored on the `longtail-languages`
  slice; see §5.

## 3. Out-of-scope use

- **Legal, tax, or financial advice.** The assistant must not produce
  statements that constitute legal, tax, or financial advice. Guardrail
  enforced at the output layer; measured on `advice-refusal-probes` (§4.4).
- **Account changes requiring identity verification.** Password resets,
  billing-address changes, and refund issuance require a verified session;
  the assistant must escalate and not carry out these changes.
- **Non-billing product support (shipping, device setup, warranty claims).**
  The assistant is not trained on these intents and must route them to the
  general-support queue.

## 4. Eval results

All numbers below are drawn from the release-gate run `eval-runs/support-assistant/rc.2-remediated@sha256:a8e...` against the baseline `models/support-assistant@v3.3.2 / eval-runs/.../baseline@sha256:4c8a...`. Each row cites its slice + metric sha in §9.

### 4.1 First-turn resolution rate (primary quality)

| Slice | Baseline | Candidate | Delta (pp) | 95% CI (pp) | Evidence row id |
|---|---|---|---|---|---|
| macro intent:billing × lang:*         | 0.812 | 0.814 | +0.2 | [-0.3, +0.6] | E-001 |
| intent:billing, lang:en               | 0.838 | 0.838 | +0.0 | [-0.4, +0.4] | E-002 |
| intent:billing, lang:es               | 0.761 | 0.775 | +1.4 | [+0.6, +2.2] | E-003 |
| intent:billing, lang:de               | 0.754 | 0.758 | +0.4 | [-0.7, +1.5] | E-004 |
| intent:billing, tier:free             | 0.796 | 0.798 | +0.2 | [-0.3, +0.6] | E-005 |
| intent:billing, tier:paid             | 0.828 | 0.831 | +0.3 | [-0.1, +0.7] | E-006 |

Between-language fairness gap (std of per-lang score, lower is better):

| Metric              | Baseline | Candidate | Delta | 95% CI | Evidence row id |
|---|---|---|---|---|---|
| std_dev across {en,es,de} | 0.042   | 0.038    | -0.004 | [-0.009, +0.000] | E-007 |

### 4.2 Hallucination rate

| Slice                     | Baseline | Candidate | Delta (pp) | 95% CI (pp) | Evidence row id |
|---|---|---|---|---|---|
| account-state-probes      | 0.3%     | 0.3%      | +0.0       | [-0.4, +0.4]| E-008 |

Measured on 200-item adversarial set curated by qa@team, refreshed 2026-10. Item-level traces in `eval-runs/.../hallucination-traces@sha256:...`.

### 4.3 Refusal success on exfiltration attempts

| Slice                             | Baseline | Candidate | Delta (pp) | 95% CI (pp) | Evidence row id |
|---|---|---|---|---|---|
| data-exfil-attempts (aggregate)   | 99.3%    | 99.5%     | +0.2       | [-0.4, +0.8]| E-009 |
| attack-family: phishing           | 98.1%    | 97.0%     | -1.1       | [-3.0, +0.7]| E-010 |
| attack-family: social-engineering | 99.0%    | 99.2%     | +0.2       | [-0.9, +1.3]| E-011 |
| attack-family: prompt-injection   | 99.5%    | 99.8%     | +0.3       | [-0.5, +1.0]| E-012 |

Note (§4.3). The phishing family shows no statistically significant regression after remediation; a prior rc.2 attempt failed this gate at 94.0% and was blocked. The remediation pass is documented in the gate history (§9).

### 4.4 Guardrail compliance

| Slice                             | Baseline | Candidate | Delta (pp) | 95% CI (pp) | Evidence row id |
|---|---|---|---|---|---|
| advice-refusal-probes             | 99.8%    | 99.8%     | +0.0       | [-0.3, +0.3]| E-013 |

### 4.5 Latency and cost

| Measure                           | Baseline  | Candidate | Evidence row id |
|---|---|---|---|
| p50 response latency (first token)| 420 ms    | 410 ms    | E-014 |
| p95 response latency              | 1.6 s     | 1.6 s     | E-015 |
| Cost per 1k turns (USD)           | $0.84     | $0.81     | E-016 |

### 4.6 Human evaluation

Pairwise preference against the baseline, 400 examples, 3 annotators each,
Krippendorff α = 0.78. Candidate preferred on 54% of pairs (95% CI [49%, 59%];
not statistically distinguishable from 50% at the declared alpha).

Evidence row E-017. Procedure in `eval-runs/.../human-protocol@sha256:...`.

## 5. Monitored but not gated

- `longtail-languages` slice (Portuguese, Italian, Dutch; 500 production samples,
  no formal gate). Resolution rate: 0.68 (CI [0.62, 0.74]). Monitored weekly;
  promoted to a gated slice when sample size reaches the detection target.

## 6. Limitations

Each limitation cites the evidence that revealed it.

- **Code-mixed Spanish-English drops ~3pp vs. pure Spanish.** Evidence: slice
  `lang:es-en-codemixed` (E-018), resolution rate 0.74 vs. 0.775 on pure
  `lang:es` (E-003). Users who code-switch mid-conversation see degraded first-turn
  resolution.
- **Sarcastic complaints about charges are misclassified ~15% of the time.**
  Evidence: `intent:billing,tone:sarcasm` slice (E-019), misclassification rate
  0.15 (CI [0.11, 0.19]). The assistant routes some sarcastic feedback as a
  resolved billing query.
- **Phishing-family refusal is the tightest safety margin.** Although the
  current candidate passes, its CI (E-010) brushes close to the 95% per-family
  floor. The red-team set for this family is scheduled for a refresh in Q1 2027
  (owner: security@team).
- **No measured performance on languages other than EN/ES/DE.** See §5. Any
  surge in a fourth language's traffic is a blind spot until a slice exists.
- **Latency measurements do not include the retrieval tier.** Numbers in §4.5
  are the model-only portion; see the system card at
  `system_cards/support-system@v3.4.0` for the end-to-end latency breakdown.

## 7. Fairness and bias

The primary fairness axis measured is language (EN/ES/DE); evidence in §4.1.
No demographic (age, gender, geography) axis is measured directly — the product
holds no user-level demographic data, and inferring demographics for eval was
deemed both infeasible (insufficient signal) and inappropriate (would require
collecting data the product otherwise does not have).

Known un-measured axes: user tenure (new vs. long-term customers), device type,
accessibility-assistive-tool users. These are flagged for monitoring as
sample size allows.

## 8. Safety and security

- Safety evaluation sets: `account-state-probes` (hallucination, §4.2),
  `data-exfil-attempts` (refusal, §4.3), `advice-refusal-probes` (guardrails,
  §4.4), and `prompt-injection` (via the exfil attempts family, §4.3).
- Red-team process: curated internally by qa@team and security@team;
  quarterly refresh; last refresh 2026-10.
- Known adversarial tactics included: direct prompt injection, indirect
  injection via retrieved content, phishing-style exfiltration, social
  engineering of account resets.
- Known adversarial tactics not covered: multi-turn jailbreaks over > 10 turns
  (compute cost), adversarial image injection (text-only product).

## 9. Evidence map and gate history

- Evidence map: `model_card_evidence.yml` (sha256:`<...>`). Each row E-00N
  resolves to (slice sha, metric sha, baseline run sha, candidate run sha,
  CI method, bootstrap seed).
- Gate manifest: `eval/gates.yml@v3.4.0` (sha256:`<...>`). See
  [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md) for the
  manifest format.
- Gate history:
  - rc.1 (2026-11-18): BLOCKED — G-012-family:phishing at 94.0%. Dispositioned,
    not overridden. Remediation: refusal-training pass on phishing family.
  - rc.2 (2026-11-20): BLOCKED — G-003 (lang:es) at -1.4pp. Dispositioned,
    not overridden. Remediation: targeted fine-tune on autopay-pause subset.
  - rc.2-remediated (2026-11-25): PASSED all gates; this card documents that
    pass.

## 10. Changelog

- v1.0 (2026-11-27): Initial release of support-assistant@v3.4.0.
```

### 2.3 Evidence map

The evidence map is the machine-readable twin of §4 and §6. The publish CI reads it, resolves each `evidence_sha256`, and fails the publish if any sha is unresolvable in the registry.

```yaml
# model_card_evidence.yml
version: 1
model_sha256: "models/support-assistant@sha256:91de4b2a..."
card_section: v3.4.0

rows:
  - id: E-001
    section: "4.1"
    claim: "macro intent:billing × lang:* resolution rate +0.2pp (not significant)"
    metric_sha256:   "metrics/first-turn-resolution-rate@sha256:5a7b..."
    slice_sha256:    "slices/intent-billing-x-lang@sha256:de32..."
    baseline_run:    "eval-runs/support-assistant/baseline@sha256:4c8a..."
    candidate_run:   "eval-runs/support-assistant/rc.2-remediated@sha256:a8e..."
    ci_method: bootstrap
    ci_level: 0.95
    bootstrap_seed: 12345
    sample_size: 6300

  - id: E-003
    section: "4.1"
    claim: "intent:billing, lang:es: resolution rate +1.4pp [+0.6, +2.2]"
    metric_sha256:   "metrics/first-turn-resolution-rate@sha256:5a7b..."
    slice_sha256:    "slices/intent-billing-lang-es@sha256:...."
    baseline_run:    "eval-runs/support-assistant/baseline@sha256:4c8a..."
    candidate_run:   "eval-runs/support-assistant/rc.2-remediated@sha256:a8e..."
    ci_method: bootstrap
    ci_level: 0.95
    bootstrap_seed: 12345
    sample_size: 1500

  - id: E-008
    section: "4.2"
    claim: "hallucination_rate on account-state-probes: 0.3% (unchanged vs baseline)"
    metric_sha256:   "metrics/hallucination-rate@sha256:...."
    slice_sha256:    "slices/account-state-probes@sha256:...."
    baseline_run:    "eval-runs/support-assistant/baseline@sha256:4c8a..."
    candidate_run:   "eval-runs/support-assistant/rc.2-remediated@sha256:a8e..."
    ci_method: bootstrap
    ci_level: 0.95
    sample_size: 200
    note: "adversarial set; floor-only gate 0.5% ceiling + delta ≤ 0.1pp"

  - id: E-010
    section: "4.3"
    claim: "attack-family:phishing refusal 97.0% (-1.1pp, CI brushes floor)"
    metric_sha256:   "metrics/refusal-success-rate@sha256:...."
    slice_sha256:    "slices/exfil-attempts-phishing@sha256:...."
    baseline_run:    "eval-runs/support-assistant/baseline@sha256:4c8a..."
    candidate_run:   "eval-runs/support-assistant/rc.2-remediated@sha256:a8e..."
    ci_method: bootstrap
    ci_level: 0.95
    sample_size: 90
    flag: "narrow margin to 95% per-family floor; refresh due Q1-2027"

  - id: E-017
    section: "4.6"
    claim: "human preference 54% [49, 59] — not distinguishable from 50%"
    protocol_sha256: "protocols/human-pairwise-preference@sha256:..."
    n_pairs: 400
    n_annotators_per_pair: 3
    reliability: {metric: krippendorff_alpha, value: 0.78}

  - id: E-018
    section: "6"
    claim: "lang:es-en code-mixed drops ~3pp vs pure es"
    metric_sha256:   "metrics/first-turn-resolution-rate@sha256:5a7b..."
    slice_sha256:    "slices/lang-es-en-codemixed@sha256:...."
    candidate_run:   "eval-runs/support-assistant/rc.2-remediated@sha256:a8e..."
    sample_size: 240
    note: "observational only; no baseline slice existed prior to this release"
```

### 2.4 Section schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "model_card.schema.json",
  "type": "object",
  "required": [
    "model_name", "model_version", "model_sha256",
    "owners", "release_date", "intended_use", "out_of_scope_use",
    "eval_results", "limitations", "safety", "evidence_map_ref",
    "card_version"
  ],
  "properties": {
    "model_name": {"type": "string"},
    "model_version": {"type": "string"},
    "model_sha256": {"type": "string", "pattern": "^models/.*@sha256:[0-9a-f]{64}$"},
    "owners": {
      "type": "object",
      "required": ["product", "eval", "safety"],
      "properties": {
        "product": {"type": "string"},
        "eval": {"type": "string"},
        "safety": {"type": "string"}
      }
    },
    "release_date": {"type": "string", "format": "date"},
    "intended_use": {"type": "string", "minLength": 50},
    "out_of_scope_use": {
      "type": "array",
      "minItems": 1,
      "items": {"type": "string", "minLength": 30}
    },
    "eval_results": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["section", "rows"],
        "properties": {
          "section": {"type": "string"},
          "rows": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["claim", "evidence_row_id"],
              "properties": {
                "claim": {"type": "string"},
                "evidence_row_id": {"type": "string", "pattern": "^E-\\d{3}$"}
              }
            }
          }
        }
      }
    },
    "limitations": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["claim", "evidence_row_id"],
        "properties": {
          "claim": {"type": "string"},
          "evidence_row_id": {"type": "string", "pattern": "^E-\\d{3}$"}
        }
      }
    },
    "safety": {
      "type": "object",
      "required": ["red_team_cadence", "last_refresh_date", "covered_tactics", "not_covered_tactics"]
    },
    "evidence_map_ref": {"type": "string"},
    "card_version": {"type": "string", "pattern": "^v\\d+\\.\\d+$"}
  }
}
```

Rules the schema encodes:

- **`intended_use` and `out_of_scope_use` are required and have minimum lengths.** A one-word intended-use string ("chat") fails the schema; so does an empty out-of-scope list.
- **Every eval-results and limitation row has an `evidence_row_id`.** A claim without an id is a claim without a receipt. The publish step verifies every id appears in `model_card_evidence.yml`.
- **Owner groups are triples (product, eval, safety).** A card without a named safety owner is rejected at publish; the gap is visible before the card ships.

### 2.5 Publish and review gate

```python
"""ci/publish_model_card.py — Publish a model card as a registry artifact.

Steps:
  1. Validate MODEL_CARD.md's YAML header + sections against model_card.schema.json.
  2. Load model_card_evidence.yml; for each row's *_sha256, call the registry
     resolver and fail if any sha is unknown or deprecated-past-sunset.
  3. Compute the card's sha256 (over the normalized MODEL_CARD.md).
  4. Register the card as model_cards/<model_id>@<model_semver>.
  5. Move the alias model_cards/<model_id>@prod when the release manager
     signs off, via the standard two-person alias-move policy
     (see mod-111 exercise-01)."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from registry_client import Registry  # mod-111 exercise-01
from schema_validate import validate_yaml_header  # local


def main(card_path: Path, evidence_path: Path) -> int:
    header = validate_yaml_header(card_path, Path("schemas/model_card.schema.json"))
    evidence = json.loads(evidence_path.read_text())  # YAML → JSON upstream

    registry = Registry.from_env()

    # (1) every evidence sha must resolve
    for row in evidence["rows"]:
        for key in ("metric_sha256", "slice_sha256",
                    "baseline_run", "candidate_run", "protocol_sha256"):
            sha = row.get(key)
            if sha is None:
                continue
            manifest = registry.resolve(sha)
            if manifest.deprecated_past_sunset:
                print(f"error: evidence {row['id']} cites sunset artifact {sha}", file=sys.stderr)
                return 2

    # (2) every eval_results / limitations row id must exist in evidence
    evidence_ids = {r["id"] for r in evidence["rows"]}
    for section in header["eval_results"]:
        for row in section["rows"]:
            if row["evidence_row_id"] not in evidence_ids:
                print(f"error: eval row cites unknown evidence id {row['evidence_row_id']}", file=sys.stderr)
                return 3
    for lim in header["limitations"]:
        if lim["evidence_row_id"] not in evidence_ids:
            print(f"error: limitation cites unknown evidence id {lim['evidence_row_id']}", file=sys.stderr)
            return 4

    # (3) compute card sha and register
    card_sha = _sha256_file(card_path)
    model_id = header["model_name"]
    semver = header["model_version"]
    registry.register(
        artifact_id=f"model_cards/{model_id}",
        artifact_type="run_config",  # cards live in the generic config space
        semver=semver,
        content_path=card_path,
        metadata={"model_sha256": header["model_sha256"], "card_version": header["card_version"]},
        parents=[header["model_sha256"]],
        signing_key_id=_signer_from_env(),
    )
    print(f"published model_cards/{model_id}@{semver} (card sha256: {card_sha})")
    return 0


def _sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for buf in iter(lambda: f.read(chunk), b""):
            h.update(buf)
    return h.hexdigest()
```

Design notes:

- **Publish is CI, not a human copy-paste.** A card that is pasted into a wiki can be edited in place; a card published through a signed CI job is an immutable registry artifact with an auditable alias move.
- **Deprecated evidence is a publish-time failure.** A card that cites an eval artifact past its sunset is a stale card; the publish refuses, forcing the author to re-cite current evidence.
- **The model's sha is a parent of the card's sha.** Lineage edges in the registry expose the relationship: a reviewer looking at the model can walk forward to the current card; a reviewer looking at the card can walk back to the model it describes.

### 2.6 Changelog policy

```markdown
# docs/card-changelog.md (excerpt)

A card gets a new `card_version` (minor or patch) when the card changes but
the model does not. Every card revision is a registry version; the alias
`model_cards/<model_id>@prod` moves only after sign-off.

| Change                                                   | Card bump | Approvers |
|---|---|---|
| New limitation added (previously un-measured slice evaluated) | minor | model-eval@team |
| Existing limitation's evidence refreshed                 | patch | card author |
| New out-of-scope entry added (narrows scope)             | minor | product owner + safety owner |
| Out-of-scope entry removed (expands scope)               | **major** | product owner + safety owner + ml-responsibility@team |
| Eval result refreshed from a new run                     | minor | model-eval@team |
| Typo / formatting                                        | patch | card author |
| Model sha changed                                        | n/a — new card |

A new model sha (`models/support-assistant@v3.5.0`) always produces a new
card at `model_cards/support-assistant@v3.5.0`; the previous card remains
in the registry under its own sha, accessible by anyone asking what v3.4.0
claimed.
```

## 3. Validation steps

1. **Schema validation.** `jsonschema MODEL_CARD.md schemas/model_card.schema.json` passes. Missing `out_of_scope_use`, missing safety owner, or an evidence id in the wrong format fails the schema.
2. **Evidence resolution.** `publish_model_card.py` resolves every `metric_sha256`, `slice_sha256`, `baseline_run`, `candidate_run`, and `protocol_sha256` in `model_card_evidence.yml`; unresolved shas or sunset-passed shas fail the publish.
3. **Cross-reference completeness.** Every `evidence_row_id` in the card appears in the evidence map; every evidence row appears somewhere in the card. A CI lint catches orphans in either direction.
4. **CI method declared.** For each evidence row with a numerical delta, `ci_method`, `ci_level`, and (where applicable) `bootstrap_seed` are set. A reviewer can rerun the bootstrap and reproduce the CI.
5. **Baseline provenance.** `baseline_run` resolves to a registered run whose model sha is the `prod`-aliased predecessor. A publish where the baseline is an unaliased or ad-hoc run fails.
6. **Fairness-axis coverage.** For every demographic axis the product claims to serve equally, the card has a §4 row and (if ≥ 2 subgroups) a gap-metric row. The lint enforces this against `claims.md` from [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md).
7. **Limitations have receipts.** Every entry in §6 names an evidence id; §6 limitations without an evidence id fail the lint.
8. **Gate history matches the release manifest.** The §9 gate history enumerates all rc.N builds; the warehouse query for this model's gate runs returns the same set.
9. **Immutable publish.** After `publish_model_card.py`, attempting to republish the same (model_id, semver) with different bytes returns the registry's "sha already registered" error.
10. **Alias audit.** Moving `model_cards/<model_id>@prod` requires two approvers and leaves a reason in `alias_history` (per registry policy in [mod-111 exercise-01](../../mod-111-eval-platform-engineering/exercise-01-versioned-registry-design/SOLUTION.md)).

## 4. Rubric or review checklist

Scored out of 12. The rubric rewards the card being **a view over eval evidence with every claim auditable to a sha**, not a prose document.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Every quantitative claim in §4 cites an evidence row with sha and CI | 2 | 1-to-1 cross-reference; publish-time lint passes. |
| R2 | §3 Out-of-scope use is non-empty, concrete, and matches product claims | 2 | ≥ 3 named out-of-scope uses; each is a concrete scenario, not a hedge. |
| R3 | §6 Limitations map to measured evidence, not speculation | 2 | Every limitation has an `evidence_row_id`. |
| R4 | §7 Fairness coverage names both measured axes and un-measured axes | 1 | Un-measured axes are enumerated with "why not measured." |
| R5 | §8 Safety names curator, cadence, covered + not-covered tactics | 1 | All four sub-elements present and current. |
| R6 | §9 Evidence map is a committed, machine-readable file; every evidence row resolves in registry | 2 | `model_card_evidence.yml` present; `publish_model_card.py` passes. |
| R7 | Card is versioned, immutable, published as a registry artifact with auditable alias moves | 1 | `model_cards/<id>@<semver>` exists; `@prod` alias has approver audit. |
| R8 | Changelog policy exists; expanding scope requires safety-owner approval | 1 | `docs/card-changelog.md` lists approval matrix. |

**Passing bar:** 9 / 12. R1, R3, and R6 are non-negotiable — a card without sha-cited evidence is unverifiable. R2 is the next most-commonly missed; cards that omit out-of-scope use shift liability to the reader.

Reviewer checklist:

- [ ] Every § 4 row cites an E-00N id; every E-00N resolves in the registry.
- [ ] Out-of-scope list has ≥ 3 concrete scenarios and matches `claims.md`.
- [ ] Every limitation in § 6 names an evidence id and a measured slice.
- [ ] Safety section names curator, refresh date, covered + not-covered tactics.
- [ ] `publish_model_card.py` ran and succeeded in CI for this (model_id, semver).
- [ ] `model_cards/<id>@prod` alias move has two approvers and an audit reason.
- [ ] Fairness section names the un-measured axes and why.
- [ ] Changelog exists; any scope-expanding change had safety-owner approval.

## 5. Common mistakes

- **Claims without receipts.** "Performs well on Spanish" instead of "resolution rate 0.775 on `lang:es`, CI [0.74, 0.76], from run `rc.2-remediated@sha256:...`". The first is prose, the second is evidence.
- **No out-of-scope section (or an empty one).** The card lists everything the model does and nothing it should not do. The result is a sales brief with no legal weight.
- **Limitations invented for completeness.** "The model may struggle with sarcasm" without a slice that measured sarcasm is a guess; readers learn to discount the section. Only list limitations the evidence exposed.
- **One accuracy number for everything.** Macro accuracy hides the subgroup regressions the product actually cares about. Report per-slice, with CIs.
- **Point estimates with no CI.** A 0.02 pp improvement that is swamped by sampling noise reads as a win in the card and a regression in the warehouse. CIs make the claim falsifiable.
- **Human-eval numbers without the reliability statistic.** "Candidate preferred 54%" from 3 annotators with no agreement coefficient is a number without a trust interval. Report Krippendorff α, n annotators, and n pairs.
- **The card lives in a wiki.** A wiki edit history is not an audit trail; nobody can tell what the card claimed a year ago. Publish it to the registry.
- **No gate history.** The card shows the final run but hides the three blocked rc.N candidates. Transparent gate history is how the card earns the risk reviewer's trust.
- **No fairness axis declared.** The product serves users in multiple languages or demographics, but the card reports only macro numbers. A fairness-aware reader asks what axes were considered and finds none.
- **Un-measured axes hidden.** A card that lists "we measured X and Y" without saying "we did not measure Z and here is why" implies Z was fine. Say what you did not measure.
- **Card version equals model version forever.** A revision to the limitations section after launch produces no new card version; readers cannot distinguish the launch-day card from the current one. Version the card independently of the model.
- **The card is written at the end.** The template is drafted at launch, so sections are copy-pasted from the last model and the evidence map is empty. Draft the card and evidence map in parallel with the gate plan ([exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md)); the gate run populates both.
- **Expanding scope without safety-owner approval.** "The assistant also supports warranty claims now" added quietly to §2. The safety evaluation set has no coverage for warranty intents; the card now mis-claims safety-tested scope.
- **No mention of what was *not* red-teamed.** A safety section that lists the tactics covered without listing the tactics not covered implies universal coverage; the first out-of-coverage incident makes the card look dishonest.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function asks that "performance be documented per context and subpopulation" — the per-slice tables with CIs are the documentation. `MANAGE` asks that "deployment decisions be traceable to the evidence that supported them" — the evidence map is the direct traceability from card claim to pinned eval artifact. `GOVERN` asks for named owners and accountability; the (product, eval, safety) owner triple satisfies this.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** motivates sha-cited evidence over prose claims — a card whose numbers can be edited in place is an integrity vector. **ML08 Model Skewing** is why the per-slice and gap-metric breakdowns must be in the card, not summarized into a single accuracy. **ML04 Membership Inference** motivates care about which slice names are disclosed in a public card (slice names are themselves information).
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0005 Deliver Model via Publicly Available Service` and `AML.T0006 Active Scanning` frame the card as the interface adversaries read before attacking; what you disclose (adversarial tactics not covered, tightest safety margins) is a trade-off between transparency and threat surface. `AML.T0043 Craft Adversarial Data` is why the safety section must name the attack families whose refusal rate was measured — a card without that enumeration gives no basis for a risk reviewer to decide whether the coverage is sufficient.

<!-- Local exercise context: The worked product (billing-chat support assistant @v3.4.0), slice taxonomy (EN/ES/DE, intent:billing, attack-family taxonomy), thresholds, and gate history are continued from [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md); they are illustrative defaults. Replace them with your product's taxonomy before adopting. Sibling exercises: the gate plan that produced the evidence this card cites is [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md); the regulatory mapping (RMF, ISO/IEC 25059, EU AI Act) that this card is one input to is [exercise-03](../exercise-03-regulatory-mapping-rmf-iso-eu-ai-act/SOLUTION.md); the registry the card is published to is specified in [mod-111 exercise-01](../../mod-111-eval-platform-engineering/exercise-01-versioned-registry-design/SOLUTION.md); the warehouse that retains the evidence rows for a-year-later audit is [mod-111 exercise-04](../../mod-111-eval-platform-engineering/exercise-04-eval-data-warehouse-and-lineage/SOLUTION.md). -->
