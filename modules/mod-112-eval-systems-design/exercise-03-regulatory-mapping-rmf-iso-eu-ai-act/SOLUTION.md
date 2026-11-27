# exercise-03 — Regulatory Mapping: NIST AI RMF, ISO/IEC 25059, and the EU AI Act — Solution

## 1. Solution overview

"We follow NIST AI RMF" is not a compliance posture; it is an aspiration. A real regulatory mapping is the document that answers, for every obligation named in the three frameworks the organization is scoped to, **which eval artifact the org produces that is the evidence**, where that artifact lives, who owns it, and how auditors retrieve it. The job of this exercise is to produce that mapping for one worked product — the billing-chat support assistant from [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md) — against the three target frameworks: NIST AI RMF (voluntary, US-origin), ISO/IEC 25059 (international consensus quality model for AI systems), and the EU AI Act (regulation, in force).

The design hinges on four non-negotiables:

- **One row per obligation, not one row per framework.** The mapping's rows are numbered obligations ("maintain a documented risk management system across the lifecycle"); the columns are "RMF reference", "ISO/IEC 25059 reference", "EU AI Act reference", "evidence artifact", "artifact owner", "retrieval path", "audit cadence". Writing it the other way around produces a comparison of frameworks; a product team cannot act on that.
- **Evidence is a pinned registry artifact, not a Google Doc link.** Every evidence cell points to a registry sha ([mod-111 exercise-01](../../mod-111-eval-platform-engineering/exercise-01-versioned-registry-design/SOLUTION.md)) or a documented location whose integrity the organization controls. A Google Doc can be rewritten in-place and the evidence changes without an auditor being able to tell.
- **Gaps are declared, not hidden.** For every obligation the product does not yet meet, the mapping has an explicit `status: gap` row with an owner and a target date. A mapping with no gaps is almost certainly dishonest — regulatory baselines move faster than org capability — and auditors read the lack of declared gaps as a red flag.
- **The mapping is itself a versioned artifact.** `compliance/mapping@v1.0.0` is a registry artifact. Each quarterly refresh is a new version; each framework revision (e.g., ISO/IEC 25059 updated or EU AI Act secondary legislation issued) triggers a review. A mapping without a version is a snapshot in time with no provenance.

The reference answer has five deliverables:

1. A **worked mapping table** (`compliance/mapping.md`) with one row per obligation across the three frameworks and one evidence cell per obligation.
2. A **framework crosswalk reference** (`docs/compliance/frameworks.md`) that names each framework's structure — RMF functions and categories; ISO/IEC 25059 quality characteristics; EU AI Act risk tiers and the high-risk obligations relevant to this system — so a reviewer can see the shape of what is being mapped against.
3. A **classification worksheet** (`compliance/classification.md`) that answers "is this system high-risk under the EU AI Act?" with a reasoned analysis before the mapping is composed. The mapping's obligations depend on the classification; the classification must therefore be first.
4. A **gap register** (`compliance/gaps.yml`) — the subset of mapping rows where `status: gap`, with owner + target date + remediation plan. The register is the operational output of the mapping.
5. A **governance surface** (`docs/compliance/governance.md`) that pins who authors the mapping, who approves gap closures, how the quarterly refresh runs, what external counsel sign-off is required, and how the mapping is retained as audit evidence.

This maps directly to the NIST AI RMF `GOVERN` function, which asks for "documented policies, processes, and roles for AI risk management with assigned accountabilities" — the mapping itself is one such policy artifact ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10: **ML09 Output Integrity Attacks** is why evidence must be a pinned sha, not a Doc link; **ML05 Model Theft / Misuse** is one specific obligation the EU AI Act's `accuracy, robustness, cybersecurity` article compels organizations to document controls against ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS techniques are the threat taxonomy the technical-documentation and post-market-monitoring obligations expect organizations to assess ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation — mapping

### 2.1 Framework structure at a glance

The three frameworks have different scopes and different enforcement teeth. The mapping reads them side-by-side.

```markdown
# docs/compliance/frameworks.md (excerpt)

## NIST AI Risk Management Framework (voluntary; US-origin)
Four functions, each with categories and subcategories:
  - GOVERN: establish and maintain policies, roles, and accountability.
  - MAP: establish context; identify risks; characterize the system.
  - MEASURE: assess risks and impacts using appropriate metrics.
  - MANAGE: prioritize, document, and act on risks.
Enforcement: none directly; referenced by US procurement and sector regulators.
Source: https://www.nist.gov/itl/ai-risk-management-framework.

## ISO/IEC 25059 — Quality model for AI systems
Extension of the SQuaRE family (ISO/IEC 25010) specialized for AI systems.
Defines AI-system quality characteristics such as functional adaptability,
user controllability, transparency, robustness, and interaction capability,
alongside the general SQuaRE characteristics (functional suitability,
performance efficiency, usability, reliability, security, maintainability,
portability).
Enforcement: as a consensus standard; adopted by national standards bodies
and by contractual reference.
<!-- reviewer-note: confirm the exact enumeration of AI-specific characteristics
and sub-characteristics in the published ISO/IEC 25059 (2023) edition,
including whether "controllability" is a top-level characteristic or a
sub-characteristic of usability. -->

## EU AI Act (Regulation (EU) 2024/1689)
Risk-tiered regulation in force in the EU:
  - Unacceptable risk: prohibited (Title II).
  - High-risk: regulated (Title III), with obligations including a risk
    management system (Art. 9), data and data governance (Art. 10),
    technical documentation (Art. 11), record-keeping/logging (Art. 12),
    transparency to deployers (Art. 13), human oversight (Art. 14),
    accuracy/robustness/cybersecurity (Art. 15), quality management system
    (Art. 17), post-market monitoring (Art. 72), and reporting of serious
    incidents (Art. 73).
  - Limited risk: transparency obligations only.
  - Minimal risk: no specific obligations beyond general law.
General-purpose AI (GPAI) models have their own Title VIIIA obligations,
with additional obligations for GPAI models with systemic risk.
Enforcement: national supervisory authorities and the EU AI Office; fines
up to a percentage of global turnover for the most serious infractions.
<!-- reviewer-note: confirm article numbers in the final consolidated
text as published in the Official Journal; this mapping cites article
numbers from the 2024 adopted text. -->
```

### 2.2 EU AI Act classification worksheet

Classification must precede mapping; the high-risk obligations only apply if the system is high-risk, and the limited-risk transparency obligations apply if it is limited-risk.

```markdown
# compliance/classification.md (excerpt)

System: support-assistant@v3.4.0 — billing-and-subscriptions chat assistant.

## Prohibited practices (Title II)
- Subliminal manipulation: no. The assistant has no persuasive-manipulation
  surface; it responds to user questions and offers factual answers.
- Exploitation of vulnerabilities: no.
- Social scoring by public authorities: no (private product).
- Real-time remote biometric identification: no.
- Emotion inference in workplaces or education: no.
- Biometric categorization inferring sensitive attributes: no.
Conclusion: system does not fall under Title II.

## High-risk classification (Annex III analysis)
Annex III lists eight high-risk use-case areas; the assistant was assessed
against each:
  - Biometric identification/categorization: not applicable.
  - Critical infrastructure management: not applicable.
  - Education / vocational training: not applicable.
  - Employment, worker management, access to self-employment: not applicable.
  - Access to and enjoyment of essential private/public services and benefits:
    **potentially applicable** — the assistant handles billing questions for
    a consumer service; under some interpretations this touches "essential
    private services" if the service is utility-like. The product (a SaaS
    subscription) is consumer-grade but not utility-like; counsel assessed
    this as not high-risk under the current interpretation. Flagged for
    re-review if implementing authorities issue guidance expanding this
    definition.
    <!-- reviewer-note: verify current EU AI Office or Commission guidance
    on scope of "essential private services" post-2025. -->
  - Law enforcement: not applicable.
  - Migration, asylum, border control: not applicable.
  - Administration of justice and democratic processes: not applicable.

Conclusion: the assistant is **not classified as high-risk** under Annex III
on the current facts. Obligations therefore limit to:
  - Limited-risk transparency: Art. 50 (users must be informed they are
    interacting with an AI system).
  - GPAI backbone compliance: if the underlying LLM is a GPAI model, the
    provider of that GPAI model carries the Title VIIIA obligations. The
    product team's responsibility is to verify provider attestations and
    retain them.

If the product expands to handle, e.g., energy-utility customer billing in
a jurisdiction that treats energy as an essential service, the classification
flips to high-risk and the full Title III obligation set (Arts. 9–15, 17, 72,
73) applies. The classification is re-run on every material scope expansion.
```

### 2.3 The mapping table

The mapping has one row per obligation. Where the system is not high-risk, high-risk-only obligations are marked `not-applicable-current-classification` with a cross-reference to `classification.md`; if the classification flips, those rows become live.

```markdown
# compliance/mapping.md (excerpt)

| # | Obligation (plain English)                                       | NIST AI RMF ref         | ISO/IEC 25059 ref                                 | EU AI Act ref                                                | Evidence artifact                                                                                   | Owner                      | Audit cadence | Status |
|---|------------------------------------------------------------------|-------------------------|---------------------------------------------------|--------------------------------------------------------------|------------------------------------------------------------------------------------------------------|----------------------------|---------------|--------|
| 1 | Document the system's intended use and out-of-scope use          | MAP 1 (context)         | Functional suitability; Transparency              | Art. 13 (transparency to deployers); Art. 50 (user notice)   | `model_cards/support-assistant@prod` §§ 2–3 (see ex-02)                                              | model-eval@team             | per-release   | meets  |
| 2 | Maintain a documented risk management system across the lifecycle| GOVERN 1; MANAGE 1       | Reliability; Security; Maintainability            | Art. 9 (RMS)†                                                | `compliance/rms.md@v2.1`; quarterly risk review minutes at `warehouse:compliance.rms_reviews`        | ml-responsibility@team      | quarterly     | meets  |
| 3 | Document the training data, its provenance, and governance       | MAP 2 (data); GOVERN 5  | Functional suitability; Data quality              | Art. 10 (data governance)†                                   | `datasets/*` lineage edges (mod-111 ex-01); `datasets/support-ft-set@prod` manifest                   | model-eval@team             | per-release   | meets  |
| 4 | Produce technical documentation covering architecture, training, evaluation, and known limitations | MAP 3; MEASURE 1; MANAGE 2 | Transparency; Reliability                   | Art. 11 + Annex IV (technical documentation)†                | `model_cards/support-assistant@prod`; `eval-runs/.../rc.2-remediated@sha256:a8e...`                   | model-eval@team             | per-release   | meets  |
| 5 | Keep automatic logs of operation ("record-keeping") sufficient for traceability | MAP 4; MEASURE 4 | Reliability; Security                             | Art. 12 (record-keeping)†                                    | Serving-tier request logs retained ≥ 180 days; warehouse table `prod.serving_requests` (see mod-110 ex-05) | platform-eng@team           | annual        | meets  |
| 6 | Enable human oversight; design for user controllability          | MANAGE 3                | User controllability; Interaction capability      | Art. 14 (human oversight)†                                   | Handoff path documented in `MODEL_CARD.md` §2; guardrail enforcement spec `docs/guardrails.md`       | support-product@team        | per-release   | meets  |
| 7 | Measure and document accuracy, robustness, cybersecurity         | MEASURE 2; MEASURE 3    | Functional suitability; Robustness; Security      | Art. 15†                                                     | `eval-runs/.../rc.2-remediated@sha256:a8e...` §§ 4.1–4.5 (see ex-02)                                | model-eval@team; security@team | per-release | meets  |
| 8 | Operate a quality management system covering AI development      | GOVERN 2–4              | Maintainability; Process maturity (ISO/IEC 25010)  | Art. 17 (QMS)†                                               | `docs/compliance/qms.md@v1.3`; audits in `warehouse:compliance.qms_audits`                           | eng-leadership@team         | annual        | gap    |
| 9 | Implement post-market monitoring for behavior changes            | MANAGE 4; MEASURE 4     | Reliability; Performance efficiency               | Art. 72†                                                     | Production regression + drift monitoring (see [mod-110 ex-04](../../mod-110-production-eval-regression/exercise-04-sequential-testing-for-continuous-monitoring/SOLUTION.md)) | model-eval@team; platform-eng@team | continuous | meets  |
| 10 | Report serious incidents to the national supervisory authority  | MANAGE 4                | Reliability                                       | Art. 73†                                                     | Incident runbook `docs/compliance/incidents.md@v1.0`; incident log `warehouse:compliance.incidents`  | ml-responsibility@team      | per-incident  | meets  |
| 11 | Notify users that they are interacting with an AI system         | MAP 1; MANAGE 3         | Transparency; User controllability                | Art. 50 (limited-risk transparency)                          | UI copy in `apps/support-chat/src/ui/disclosure.tsx`; pre-release accessibility review                | support-product@team        | per-release   | meets  |
| 12 | For GPAI backbone: verify provider's Title VIIIA attestations    | GOVERN 5 (3rd parties)  | Compliance; Interoperability                      | Arts. 53–55 (GPAI providers); Deployer-side verification      | Provider attestations retained at `compliance/providers/<provider>@sha256:...`                       | ml-responsibility@team       | per-provider release | meets |
| 13 | Measure fairness and document demographic coverage               | MEASURE 2.1 (bias)      | Functional suitability — fairness aspects         | Art. 10 (data governance — bias) and Art. 15 (robustness)†    | `MODEL_CARD.md` §§ 4.1, 7; `eval-runs/.../fairness-gap@sha256:...`                                    | ml-responsibility@team      | per-release   | meets  |
| 14 | Red-team for safety and security-adjacent failures               | MEASURE 2.2             | Security; Robustness                              | Art. 15 (robustness/cybersecurity)†                          | `eval-runs/.../red-team-exfil@sha256:...` (see mod-109 ex-02, ex-05)                                 | security@team               | quarterly refresh | meets |
| 15 | Record keeping of eval runs and gate decisions with provenance   | MEASURE 4; MANAGE 2     | Maintainability; Reliability                      | Art. 12†                                                     | Warehouse `eval_runs`, `gates`, `dispositions`, `overrides` (see mod-111 ex-04)                      | platform-eng@team           | annual        | meets  |

† = applies to high-risk systems only; included here as a forward-looking row,
  marked `applies-if-reclassified` in the full table's `status` column so a
  reclassification would not require a from-scratch mapping rewrite.
```

Design rules this table enforces:

- **Framework references are to functions, characteristics, and articles — not to prose.** A reader can go to the primary source and verify. The mapping does not paraphrase the source into its own language and then lose the citation.
- **Evidence cells are machine-resolvable.** `model_cards/support-assistant@prod`, `warehouse:compliance.qms_audits` are URIs an auditor retrieves; `docs/compliance/rms.md@v2.1` is a registry sha. "Some wiki" is not an acceptable evidence cell.
- **Owners are routable teams.** The individual rotates; the team persists. An individual-name owner is a lint failure.
- **A row with `status: gap` is normal.** Row 8's QMS gap is an operational signal, not a shame marker. The gap register picks it up.
- **The three-framework columns are complementary, not competing.** A row cites all three; different frameworks name similar obligations in different language. The side-by-side exposure makes drift visible when a framework revision arrives.

### 2.4 Gap register

```yaml
# compliance/gaps.yml
version: 1
closes_by: 2027-03-31

gaps:
  - mapping_row: 8
    obligation: "Operate a quality management system covering AI development (EU AI Act Art. 17; RMF GOVERN 2–4; ISO/IEC 25059 — Maintainability)"
    current_state: >
      QMS v1.3 covers general engineering processes but has not yet been
      extended to cover eval-plan sign-off, red-team scheduling, and
      incident-handling specific to the AI system. External audit scheduled
      for Q1 2027 will attest to the AI-specific extension.
    owner: eng-leadership@team
    target_date: 2027-03-15
    remediation_steps:
      - "Extend QMS v1.4 draft with AI-specific procedures by 2027-01-31."
      - "Internal audit dry-run by 2027-02-28."
      - "External audit (ISO 9001-aligned) by 2027-03-15."
    status: open
    last_reviewed: 2026-11-20

  - mapping_row: "classification"
    obligation: "Re-run EU AI Act Annex III classification if scope expands to utility-like services"
    current_state: >
      Classification worksheet (classification.md) notes the possibility
      that an expansion into utility customer-service domains could flip
      the system to high-risk. No material scope expansion is on the
      current roadmap; however, the classification review is not yet
      wired to the product-roadmap change-control process.
    owner: ml-responsibility@team
    target_date: 2026-12-31
    remediation_steps:
      - "Add a 'regulatory classification review required' gate to the
         product roadmap change-control checklist by 2026-12-20."
    status: open
    last_reviewed: 2026-11-20
```

### 2.5 Governance surface

```markdown
# docs/compliance/governance.md (excerpt)

## Mapping authorship and approval
- Draft author: ml-responsibility@team.
- Legal reviewer: internal counsel (required sign-off before `@prod` alias moves).
- Technical reviewer: model-eval@team + platform-eng@team.
- The mapping is published to the registry as
  `compliance/mapping@<semver>`; `@prod` requires two approvers +
  counsel sign-off, logged in the registry's `aliases` audit table.

## Refresh cadence
- Quarterly end-of-quarter review: each row's evidence is verified still
  resolvable and still current; stale rows generate gap entries.
- Event-driven refresh:
  - EU AI Act secondary legislation or EU AI Office guidance issued.
  - ISO/IEC 25059 revision published.
  - NIST AI RMF revision published (currently 1.0; updates are tracked).
  - Material product scope change that could affect Annex III classification.
  - Serious incident (triggers RMS and incident-reporting review).

## Gap closure approval
- Closing a gap requires evidence that the obligation is met: a registry sha
  for the evidence artifact + sign-off from the row's owner + counsel
  concurrence for externally-attested obligations (e.g., ISO 9001 audit).

## Retention
- Mapping versions are retained indefinitely in the registry.
- Evidence artifacts are retained per the organization's data-retention
  policy (see `docs/compliance/retention.md`), with a minimum of seven
  years for anything that could be subject to an EU AI Act Art. 12
  record-keeping request.
```

## 3. Validation steps

1. **Classification worksheet precedes mapping.** `git log` for `compliance/classification.md` shows a commit date on or before the first `compliance/mapping.md` commit. A mapping written before classification is a mapping that may assume the wrong obligation set.
2. **Each framework reference resolves to the primary source.** For each row, the RMF reference is a function/category identifier (e.g., `MAP 2`), the ISO/IEC 25059 reference is a characteristic identifier, and the EU AI Act reference is an Article number. A reviewer can click through to the published text. `<!-- reviewer-note: ... -->` comments remain for any reference the author could not verify.
3. **Every evidence cell resolves.** `scripts/verify_evidence.py compliance/mapping.md` iterates over cells and calls the registry/warehouse resolver; unresolvable cells fail the check.
4. **Every owner is a routable team.** `scripts/check_owners.py` validates owners against the org directory.
5. **Gap register matches the mapping.** Every row in `compliance/mapping.md` with `status: gap` has a matching entry in `gaps.yml`; every entry in `gaps.yml` corresponds to a mapping row (or is a scope-triggered classification row, explicitly labeled).
6. **High-risk rows are correctly marked.** Rows flagged with `†` are marked `applies-if-reclassified` in the live mapping if the classification is not high-risk; a check enforces: "if classification.md concludes not high-risk, then no row that cites an Art. 9–17 obligation has status `meets` without an `applies-if-reclassified` qualifier." This prevents a team from accidentally claiming to meet high-risk obligations it does not need to meet (and may not actually meet).
7. **Cross-reference to other modules.** Rows pointing to post-market monitoring, red-team evidence, and warehouse lineage link to the implementing modules ([mod-109](../../mod-109-safety-and-red-team-eval/README.md), [mod-110](../../mod-110-production-eval-regression/README.md), [mod-111](../../mod-111-eval-platform-engineering/README.md)). Broken links fail the lint.
8. **Quarterly refresh log.** `compliance/refresh-log.md` has a dated entry each quarter with the reviewer name and what changed. Missing quarterly entries become a mapping gap of their own at the next refresh.
9. **Counsel sign-off on the `@prod` alias move.** `aliases.alias_history` in the registry has a `reason` field referencing the counsel sign-off ticket id; a CI lint checks the last `@prod` move has a non-empty counsel reference.
10. **Framework revision tracker.** `compliance/framework-versions.md` names the version of each framework the current mapping was written against (NIST AI RMF 1.0 or current revision; ISO/IEC 25059 — publication year; EU AI Act — Regulation (EU) 2024/1689 as amended). A newer framework version triggers an event-driven refresh.

## 4. Rubric or review checklist

Scored out of 12. The rubric rewards the mapping being **a routable operational document with versioned evidence**, not a compliance narrative.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Classification worksheet is present, reasoned, and precedes the mapping | 2 | `classification.md` enumerates Annex III categories with an applicability call for each; commit date ≤ mapping commit date. |
| R2 | Mapping has one row per obligation (not one row per framework) | 1 | Table structure: columns are RMF / ISO / EU AI Act / evidence / owner; rows are obligations. |
| R3 | Each obligation cites a primary-source reference in each applicable framework | 2 | RMF function/category id; ISO/IEC 25059 characteristic; EU AI Act article. `reviewer-note` markers are explicit, not implicit. |
| R4 | Each evidence cell resolves to a registry sha or a documented warehouse/path with retention guaranteed | 2 | `verify_evidence.py` passes; no wiki or ad-hoc Doc links used as evidence. |
| R5 | Owners are routable teams, not individuals | 1 | `check_owners.py` passes. |
| R6 | Gap register exists; every `status: gap` row has an owner, a target date, and remediation steps | 1 | `gaps.yml` matches mapping rows 1:1 for gaps; no gap without a plan. |
| R7 | High-risk-only obligations are correctly marked `applies-if-reclassified` when classification is not high-risk | 1 | No `meets` on Arts. 9–17 if classification is not high-risk; no `n/a` on Art. 50 or GPAI verification. |
| R8 | Governance surface pins authors, approvers, refresh cadence, counsel sign-off, and retention | 1 | `governance.md` has all five sections. |
| R9 | Framework-version tracker is maintained | 1 | `framework-versions.md` names the version of each framework the mapping was last reconciled to; dated within the last quarter. |

**Passing bar:** 9 / 12. R1 and R4 are non-negotiable — a mapping without classification mis-states obligations; a mapping without resolvable evidence cannot be audited.

Reviewer checklist:

- [ ] Classification was performed before the mapping; both documents are committed.
- [ ] Each row names one obligation and cites it across all three frameworks.
- [ ] Every evidence cell is a registry sha or a documented warehouse table.
- [ ] Every owner is a team; `check_owners.py` passes.
- [ ] `gaps.yml` matches `mapping.md`; every gap has an owner, target date, and plan.
- [ ] Rows that apply only to high-risk systems are marked correctly given classification.
- [ ] Counsel sign-off on the latest `@prod` alias move is recorded.
- [ ] Framework-version tracker is current.
- [ ] `reviewer-note` comments are explicit and tracked as mini-gaps.

## 5. Common mistakes

- **Starting with "we comply with X" and mapping after.** The mapping should start from the obligations in X and ask "what evidence do we have?". Starting from evidence and labeling it with framework references after the fact produces post-hoc compliance theater.
- **Skipping the classification worksheet.** Writing high-risk-tier obligations into the mapping without first analyzing Annex III produces either (a) over-compliance (the team meets rules it does not need to meet), which is cheap but misleading in auditor conversations, or (b) a mapping that confidently claims high-risk compliance without the controls those rules require.
- **Prose paraphrases instead of primary-source references.** "The RMF asks that we measure things" is unverifiable; `MEASURE 2` is a function/category identifier an auditor can look up. Cite by identifier.
- **Evidence cells pointing to Google Docs.** A Doc can be edited in place; a sha cannot. Publish evidence as registry artifacts.
- **No gaps declared.** Every regulatory mapping has gaps; a mapping without declared gaps is either dishonest or was written against an obsolete framework version. Declare them.
- **"n/a" with no reasoning.** Marking an obligation `not applicable` without the one-sentence reason in the mapping (or in the classification worksheet it references) leaves the next reader with no basis to agree or disagree.
- **Owner = individual name.** The individual rotates; the gate loses its owner. Teams with group routing.
- **Mapping lives in a wiki.** The mapping cannot be referenced by audits if its history is wiki edits; put it in the registry with versions and alias audit.
- **No governance for the mapping itself.** Who approves a change? Who signs off `@prod`? Without a documented approval process the mapping is "whatever the most recent edit says."
- **Frameworks treated as interchangeable.** NIST AI RMF is voluntary and US-focused; ISO/IEC 25059 is a consensus standard with adoption; the EU AI Act is regulation with fines. Confusing the three leads to under-compliance with the hardest (EU AI Act) and over-generalization of the others.
- **One-off mapping with no refresh.** The mapping is composed at launch and never revisited; six months later the EU AI Office issues secondary guidance and the mapping is stale. Quarterly refresh plus event-driven triggers.
- **Treating GPAI obligations as the deployer's problem to document from scratch.** If the backbone is a GPAI model, the model's provider holds the Title VIIIA obligations; the deployer retains provider attestations and verifies them. The deployer does not re-document the GPAI obligations from scratch but also does not assume compliance without attestations.
- **Ignoring post-market monitoring (Art. 72).** Teams focus on the pre-release obligations because they are ticked at launch; Art. 72 is a continuous obligation whose evidence is the production regression suite's existence and health ([mod-110](../../mod-110-production-eval-regression/README.md)). Treat it as a monitoring program, not a one-time document.
- **No tracking of framework versions.** A mapping written against ISO/IEC 25059 (2023) that is not re-verified against ISO/IEC 25059 (202N) silently loses accuracy. Track the framework version alongside the mapping version.
- **Counsel sign-off treated as optional.** The EU AI Act carries real penalties; a mapping without counsel sign-off is a mapping whose errors are the engineering team's alone. Get counsel in the alias-move approval path.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. Function identifiers (`GOVERN`, `MAP`, `MEASURE`, `MANAGE`) and their numbered categories/subcategories are the identifiers this mapping cites for every row. The `GOVERN` function in particular asks for "documented policies, processes, and roles for AI risk management with assigned accountabilities" — the mapping document itself is one such policy artifact.
- ISO/IEC 25059 — AI-system quality model (extension of SQuaRE). Cited in each mapping row by named quality characteristic. The published 2023 edition names AI-specific characteristics on top of the SQuaRE (ISO/IEC 25010) general characteristics; specific sub-characteristic enumeration is noted as `reviewer-note` where the author could not verify against the published text. Official page: <https://www.iso.org/standard/80655.html>.
- EU AI Act (Regulation (EU) 2024/1689). Risk-tiered regulation; cited in each row by Article number. The mapping cites specific Articles for the most common obligations: Art. 9 (risk management system), Art. 10 (data and data governance), Art. 11 (technical documentation), Art. 12 (record-keeping / logging), Art. 13 (transparency to deployers), Art. 14 (human oversight), Art. 15 (accuracy, robustness, cybersecurity), Art. 17 (quality management system), Art. 50 (limited-risk transparency obligations), Arts. 53–55 (GPAI provider obligations), Art. 72 (post-market monitoring), Art. 73 (serious incident reporting). <!-- reviewer-note: confirm final Article numbering in the consolidated OJ-published text; the 2024 adopted text numbering is used here. --> Official source: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj>.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML09 Output Integrity Attacks** motivates evidence-as-pinned-sha (vs. mutable Doc links) — a mapping whose evidence can be rewritten in place offers no audit guarantee. **ML05 Model Theft / Model Misuse** and **ML06 AI Supply Chain Attacks** are threats the EU AI Act Art. 15 (cybersecurity) and Art. 10 (data provenance) oblige organizations to address.
- MITRE ATLAS — <https://atlas.mitre.org/>. The ATLAS matrix is the threat taxonomy that the Art. 11 technical documentation and Art. 72 post-market monitoring obligations expect organizations to assess against. Mapping rows 14 (red-teaming) and 9 (post-market monitoring) draw their methodology from here.

<!-- Local exercise context: The worked product is the billing-chat support assistant continued from [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md) and [exercise-02](../exercise-02-model-card-from-eval-evidence/SOLUTION.md); the classification conclusion (not high-risk under current Annex III interpretation) and the gap set (QMS extension, classification-review change-control) are illustrative and reflect one plausible product profile. Replace them with your product's classification, evidence inventory, and real gap set before adopting. The `reviewer-note` markers in the frameworks reference and the EU AI Act article numbering indicate specific points where primary-source verification is required before publishing to `@prod`. Sibling exercises: the release gate plan whose evidence populates rows 4, 7, 13, and 14 is [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md); the model card that is cited by rows 1, 4, 11, and 13 is [exercise-02](../exercise-02-model-card-from-eval-evidence/SOLUTION.md); the build-vs-buy decision for the platform underpinning rows 2, 5, 9, and 15 is [exercise-04](../exercise-04-build-vs-buy-platform-matrix/SOLUTION.md). -->
