# exercise-04 — Build-vs-Buy Platform Matrix and Budget Defense — Solution

## 1. Solution overview

"Should we build or buy the eval platform?" is usually asked as a procurement question, but it is a product question: what is the eval platform **for**, over what horizon, and against what competing claims on engineering time and budget? Answered procurementally it produces either (a) a signed vendor contract the engineering org cannot operate, or (b) a half-built internal platform that falls behind the eval field two quarters after the first demo. Answered as a product question it produces a **matrix** — one row per platform capability, one column per candidate, with explicit scoring, explicit assumptions, and a defensible budget attached — that can survive a VP-level budget review and a six-month retrospective.

The design hinges on four non-negotiables:

- **Capabilities, not vendors.** The matrix's rows are the capabilities the organization needs ("artifact registry with content-addressing and lineage", "judge calibration and drift tracking", "SLO-aware release gates"). The columns are candidates, one of which is "build in-house." A matrix that leads with "Vendor A vs. Vendor B" and never writes down the capability list produces a comparison optimized for the vendors' marketing material, not for the org's needs.
- **Total cost of ownership over three years, not license sticker price.** A $30k/yr platform that requires 1.5 FTE to integrate and operate costs more than a $300k/yr managed platform with a one-engineer integration. The budget defense models both: license + integration + ongoing operations + exit cost. The three-year horizon is chosen because the eval field moves faster than that; the matrix is explicit that the decision will be revisited.
- **The "do nothing" column is a real column.** Teams reach for build-vs-buy and forget that "keep running the notebook-plus-CSV status quo for six more months while we hire a platform engineer" is a candidate with its own cost and its own risk. The matrix forces an explicit comparison; the status quo must defend itself.
- **Scoring is a function of weights, and weights are written down.** A platform that is "better at X" and "worse at Y" is not comparable until X and Y are weighted by the business. Weights are signed off by the budget owner before scoring starts; changing weights after scoring is a flag the matrix was gamed.

The reference answer has five deliverables:

1. A **capability inventory** (`platform/capabilities.md`) — the canonical list of capabilities the eval platform must provide (or defer), each with a one-sentence definition, a weight, and a pointer to the sibling-module exercise that implements it.
2. A **candidate list** (`platform/candidates.md`) — the alternatives being evaluated, including at minimum: "build in-house," "buy managed platform X," "buy managed platform Y," "assemble from open-source components," and "status quo".
3. A **scoring matrix** (`platform/matrix.yml`) — rows are capabilities, columns are candidates; cells hold a 0–3 score per capability with a one-line justification.
4. A **three-year TCO model** (`platform/tco.md`) with per-year license, integration, ongoing-ops, and exit-cost estimates and a sensitivity table ("what if we miss our growth forecast by 2x").
5. A **budget defense memo** (`platform/budget-defense.md`) — the artifact that goes to the funding review: recommendation, two alternative recommendations we rejected and why, assumptions, risks, revisit trigger.

This maps directly to the NIST AI RMF `GOVERN` function, which asks for "documented policies, processes, and roles for AI risk management with assigned accountabilities, informed by cost and risk trade-offs across the lifecycle"; the matrix and budget defense are the operational form of the cost/risk trade-off ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML06 AI Supply Chain Attacks** — a managed vendor is a supply-chain dependency and must be scored on its own attack surface, not treated as "someone else's problem" ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0010 ML Supply Chain Compromise` is the explicit threat model the vendor-security row of the matrix defends against ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation — matrix and budget defense

### 2.1 Capability inventory

Capabilities are derived from the sibling modules; this exercise does not invent them. The weights express the business's priorities; they are signed off before scoring.

```markdown
# platform/capabilities.md (excerpt)

| Cap ID | Capability                                                   | Weight | Reference |
|---|---|---|---|
| C1 | Versioned artifact registry with content addressing + lineage | 3 | [mod-111 ex-01](../../mod-111-eval-platform-engineering/exercise-01-versioned-registry-design/SOLUTION.md) |
| C2 | Multi-runner orchestration (batched / streaming / human)      | 2 | [mod-111 ex-02](../../mod-111-eval-platform-engineering/exercise-02-multi-runner-orchestration/SOLUTION.md) |
| C3 | Platform cost controls and per-team budgets                   | 2 | [mod-111 ex-03](../../mod-111-eval-platform-engineering/exercise-03-platform-cost-controls/SOLUTION.md) |
| C4 | Eval data warehouse with lineage and audit views              | 3 | [mod-111 ex-04](../../mod-111-eval-platform-engineering/exercise-04-eval-data-warehouse-and-lineage/SOLUTION.md) |
| C5 | Eval in CI with SLO-linked gates                              | 3 | [mod-111 ex-05](../../mod-111-eval-platform-engineering/exercise-05-eval-in-ci-with-slo/SOLUTION.md) |
| C6 | LLM-as-judge calibration + drift tracking                     | 3 | [mod-105](../../mod-105-llm-as-judge-platforms/README.md) |
| C7 | Human-eval workflow with annotator-reliability tracking       | 2 | [mod-106](../../mod-106-human-evaluation/README.md) |
| C8 | Production regression + drift + shadow comparison             | 3 | [mod-110](../../mod-110-production-eval-regression/README.md) |
| C9 | Safety / red-team eval surfaces (refusal, jailbreak, injection) | 3 | [mod-109](../../mod-109-safety-and-red-team-eval/README.md) |
| C10 | Release-gate workflow with disposition audit                 | 3 | [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md) |
| C11 | Compliance evidence retention (EU AI Act / RMF / 25059)       | 3 | [exercise-03](../exercise-03-regulatory-mapping-rmf-iso-eu-ai-act/SOLUTION.md) |
| C12 | Vendor security posture (SOC 2, data residency, sub-processor list) | 2 | n/a — a buy-side-only capability |
| C13 | Portability / exit path (export formats, schema versioning)   | 2 | — |

Weights: 1 = nice-to-have; 2 = important; 3 = release-blocking.

Weight sign-off: VP Eng (budget owner) + Head of ML Responsibility
+ Head of Model Eval. Signed 2026-11-10; re-ratified at every quarterly refresh.
```

Design rules:

- **Weight sign-off happens before scoring.** The three signatories agree on weights without seeing any candidate's score. Changing a weight after scoring is a flag the matrix is being gamed.
- **Weights are coarse (1/2/3) not fine (0.1 increments).** A 2.3-vs-2.4 argument is noise. 1/2/3 forces clarity: is this a release blocker or not.
- **Capabilities carry a sibling-module pointer.** A reviewer who wants to know what "versioned artifact registry with content addressing + lineage" means does not read this matrix's definition; they read the sibling module. The matrix does not reinvent concepts.
- **A capability can have "n/a" for some candidates.** Row C12 (vendor security posture) is n/a for "build in-house"; the TCO model captures the equivalent internal cost separately.

### 2.2 Candidate list

```markdown
# platform/candidates.md (excerpt)

| Candidate ID | Description                                                           |
|---|---|
| K1 | Build in-house: a dedicated platform team of 3 engineers, 18-month build horizon |
| K2 | Buy managed platform A (hypothetical commercial product; serves C1–C5 and C8; does not natively serve C6–C7, C9, C10, C11) |
| K3 | Buy managed platform B (hypothetical commercial product; serves C1–C7 strongly; weaker on C8–C11) |
| K4 | Assemble from open-source components (MLflow for C1; Airflow for C2; a self-hosted judge platform for C6; etc.) |
| K5 | Status quo: notebooks + CSVs + ad-hoc CI; 0 FTE platform investment |

Candidate selection: K2 and K3 are placeholders in this worked example; in a
real matrix the organization performs vendor outreach and names specific
products. `<!-- reviewer-note: name the actual candidate products,
license tiers, and SOC 2 report dates as of the current procurement
cycle. -->`
```

### 2.3 Scoring matrix

Scores are 0–3 (0 = absent, 1 = partial, 2 = meets, 3 = exceeds) with a one-line justification per cell. The weighted sum is reported but is not the decision; the decision reads the matrix as a whole, with explicit attention to any `release-blocking` capability (weight 3) that scored ≤ 1 on any candidate.

```yaml
# platform/matrix.yml
version: 1
weight_signoff:
  date: 2026-11-10
  signatories: ["vp-eng@team", "head-ml-responsibility@team", "head-model-eval@team"]

candidates:
  - id: K1
    name: "Build in-house (3-eng team, 18mo)"
  - id: K2
    name: "Buy managed platform A"
  - id: K3
    name: "Buy managed platform B"
  - id: K4
    name: "Open-source assembly"
  - id: K5
    name: "Status quo"

rows:
  - cap: C1
    weight: 3
    scores:
      K1: {score: 3, why: "Design exactly fits our registry policy (mod-111 ex-01); content-addressing + lineage + alias audit."}
      K2: {score: 1, why: "Has a registry concept but no content-addressed lineage DAG; no alias audit."}
      K3: {score: 2, why: "Content-addressed; lineage is a DAG; alias audit is announced-roadmap, not GA."}
      K4: {score: 2, why: "MLflow registry gives versioning; lineage requires glue code; alias audit must be built."}
      K5: {score: 0, why: "No registry."}

  - cap: C2
    weight: 2
    scores:
      K1: {score: 2, why: "Orchestration is a solved ops problem; 3 eng-months to integrate standard job runner."}
      K2: {score: 3, why: "Native batched + streaming + human-in-the-loop runners."}
      K3: {score: 3, why: "Same as K2."}
      K4: {score: 2, why: "Airflow + a human-eval tool; glue is non-trivial but tractable."}
      K5: {score: 0, why: "Runs are one-off notebooks."}

  - cap: C3
    weight: 2
    scores:
      K1: {score: 2, why: "Budget guard pattern is standard; 2 eng-months (mod-111 ex-03)."}
      K2: {score: 2, why: "Per-team cost views exist; per-run estimate not surfaced."}
      K3: {score: 1, why: "Cost is aggregated monthly; no per-run estimate; no budget guard."}
      K4: {score: 1, why: "Cloud-provider cost explorer; no eval-aware budgeting."}
      K5: {score: 0, why: "Bills surprise the finance team."}

  - cap: C4
    weight: 3
    scores:
      K1: {score: 3, why: "Warehouse design in mod-111 ex-04 fits our existing data stack."}
      K2: {score: 1, why: "Proprietary analytics; no raw-row export; no lineage joins across runs."}
      K3: {score: 2, why: "SQL export supported; lineage is partial."}
      K4: {score: 2, why: "Write to our warehouse directly; pipeline is our code."}
      K5: {score: 0, why: "CSVs."}

  - cap: C5
    weight: 3
    scores:
      K1: {score: 3, why: "CI integration is a workflow file (mod-111 ex-05); we own the gate logic."}
      K2: {score: 2, why: "Native CI integration; gate thresholds configurable; SLO linkage requires bespoke."}
      K3: {score: 2, why: "Same as K2."}
      K4: {score: 2, why: "GitHub Actions + our own gate script; standard."}
      K5: {score: 0, why: "No CI gate."}

  - cap: C6
    weight: 3
    scores:
      K1: {score: 2, why: "Judge calibration is nontrivial; 6 eng-months."}
      K2: {score: 1, why: "No native judge calibration tooling."}
      K3: {score: 3, why: "Native judge calibration + drift tracking; strong feature."}
      K4: {score: 1, why: "OSS judge platforms exist but calibration is rough."}
      K5: {score: 0, why: "Judges run as ad-hoc scripts."}

  - cap: C7
    weight: 2
    scores:
      K1: {score: 2, why: "4 eng-months to build minimal human-eval workflow; reliability tracking standard."}
      K2: {score: 1, why: "External tool integration; annotator-reliability is bring-your-own."}
      K3: {score: 2, why: "Built-in human-eval; reliability via Krippendorff/ICC."}
      K4: {score: 2, why: "Label Studio + our aggregator; standard."}
      K5: {score: 1, why: "We do human eval today but reliability is not tracked."}

  - cap: C8
    weight: 3
    scores:
      K1: {score: 3, why: "Production regression stack (mod-110) is what the org already needs anyway."}
      K2: {score: 2, why: "Native production regression; CUPED not supported; shadow launch is supported."}
      K3: {score: 1, why: "Production monitoring is weak; focus is on offline."}
      K4: {score: 2, why: "Our prod stack already emits metrics; glue is modest."}
      K5: {score: 0, why: "No production regression view."}

  - cap: C9
    weight: 3
    scores:
      K1: {score: 2, why: "We build on OSS harms taxonomies (mod-109); credible."}
      K2: {score: 1, why: "Safety eval is a roadmap item."}
      K3: {score: 2, why: "Includes a safety eval starter kit; not comprehensive."}
      K4: {score: 2, why: "Harness/lm-eval plus red-team sets; owned by us."}
      K5: {score: 1, why: "Ad-hoc red-team runs exist."}

  - cap: C10
    weight: 3
    scores:
      K1: {score: 3, why: "Gate workflow (ex-01) + disposition audit; our product-release path."}
      K2: {score: 1, why: "Gate concept present; disposition audit must be bolted on."}
      K3: {score: 2, why: "Native release-gate concept; disposition audit partial."}
      K4: {score: 2, why: "We implement the gate in CI (mod-111 ex-05); standard."}
      K5: {score: 0, why: "No gate."}

  - cap: C11
    weight: 3
    scores:
      K1: {score: 3, why: "Compliance evidence is registry artifacts (ex-03); native."}
      K2: {score: 1, why: "Audit log export exists; no evidence-sha linkage."}
      K3: {score: 2, why: "Export + retention aligned with ISO; EU AI Act artifact patterns not yet documented."}
      K4: {score: 2, why: "Our own retention + lineage; we are the auditor."}
      K5: {score: 0, why: "Evidence does not exist in a retrievable form."}

  - cap: C12
    weight: 2
    scores:
      K1: {score: null, why: "n/a — vendor security posture inapplicable; see internal controls in matrix note."}
      K2: {score: 2, why: "SOC 2 Type II; data residency EU/US; sub-processors disclosed."}
      K3: {score: 3, why: "SOC 2 Type II + ISO 27001; data residency EU only; sub-processors with notice."}
      K4: {score: null, why: "n/a — mix of OSS components; security is per-component + our own ops."}
      K5: {score: null, why: "n/a"}

  - cap: C13
    weight: 2
    scores:
      K1: {score: 3, why: "We own the formats; exit is to ourselves."}
      K2: {score: 1, why: "Export in proprietary format; schema not versioned externally."}
      K3: {score: 2, why: "SQL + CSV export; schema documented; some proprietary fields."}
      K4: {score: 3, why: "OSS formats; exit path is swap-a-component."}
      K5: {score: 1, why: "CSVs are portable but history is lossy."}
```

**Weighted totals (sum of weight × score):**

| Candidate | Weighted sum | Max possible | Normalized (0–1) |
|---|---|---|---|
| K1 (Build in-house) | 86 | 102 | 0.843 |
| K2 (Managed A)      | 50 | 102 | 0.490 |
| K3 (Managed B)      | 77 | 102 | 0.755 |
| K4 (OSS assembly)   | 73 | 102 | 0.716 |
| K5 (Status quo)     | 10 | 102 | 0.098 |

**Release-blocking (weight-3) capabilities that scored ≤ 1 per candidate:**

| Candidate | Blocking gaps |
|---|---|
| K1 | None. |
| K2 | C1 (registry/lineage), C4 (warehouse), C8 partial, C9 (safety), C10 (gate workflow), C11 (compliance). **Six blocking gaps; this candidate is not viable without substantial self-build on top.** |
| K3 | C8 (production regression). One blocking gap — remediable with a modest in-house integration. |
| K4 | C6 (judge calibration). One blocking gap — remediable but costs engineering time. |
| K5 | C1, C4, C5, C6, C8, C9, C10, C11. **Eight blocking gaps; not viable.** |

The weighted sum alone would favor K1 (0.843) narrowly over K3 (0.755); the blocking-gap analysis sharpens the picture: K2 is effectively off the table; K5 is a "maintain status quo and do nothing" option that is dominated by every other candidate; K3 and K4 are each close to K1 after remediation of their single blocking gap. The TCO model breaks the tie.

### 2.4 Three-year TCO model

```markdown
# platform/tco.md (excerpt)

## Assumptions
- Horizon: 3 years (fiscal 2027–2029).
- Headcount costs: loaded $240k/year/eng (internal rate including benefits + overhead).
- Growth assumption: eval volume 3x over 3 years; ops cost grows sub-linearly.
- Exit-cost assumption: migrating off a managed platform back to in-house costs
  equivalent to a 6-month 2-eng project.

## TCO table ($k, 3-year total)

| Line                                   | K1 (Build) | K2 (Managed A) | K3 (Managed B) | K4 (OSS) | K5 (Status quo) |
|---|---:|---:|---:|---:|---:|
| License / subscription (yr 1–3)        |      0 |   90 (yr1) + 110 (yr2) + 130 (yr3) = 330 | 240 + 270 + 300 = 810 |       0 | 0 |
| Integration (yr 1)                     |  3 eng × 18 mo ≈ 1,080 | 2 eng × 6 mo ≈ 240 | 2 eng × 6 mo ≈ 240 | 2 eng × 9 mo ≈ 360 | 0 |
| Remediation of blocking gaps           |  — | 3 eng × 12 mo ≈ 720 (to close 6 gaps) | 1 eng × 6 mo ≈ 120 (C8 integration) | 1.5 eng × 6 mo ≈ 180 (C6 calibration) | — |
| Ongoing operations (yr 2–3)            |  1.5 eng × 24 mo ≈ 720 | 1 eng × 24 mo ≈ 480 | 1 eng × 24 mo ≈ 480 | 1.5 eng × 24 mo ≈ 720 | 1 eng × 24 mo (support ops) ≈ 480 |
| Compliance evidence retention          |  included in platform build | 100 (tooling + legal) | 60 | 100 | 150 (hardest without the platform) |
| **3-year TCO (point estimate)**        | **1,800** | **1,870** | **1,710** | **1,360** | **630** |
| Exit cost (if we leave at month 36)    |      0 | 480 | 480 | 0 | — |

## Sensitivity (what if volume grows 2x more than planned)

| Candidate | Nominal TCO | High-growth TCO | Change |
|---|---:|---:|---:|
| K1       | 1,800 | 1,920 (ops only; license is free) | +7% |
| K2       | 1,870 | 2,200 (license scales with volume) | +18% |
| K3       | 1,710 | 2,040 | +19% |
| K4       | 1,360 | 1,510 | +11% |
| K5       | 630   | 820   | +30% (ops burden dominates) |

## Risk-adjusted TCO

| Candidate | Key risk                                        | Adjustment |
|---|---|---|
| K1       | 18-mo build slips; interim period is status-quo risk | +20% |
| K2       | Vendor pricing power + 6 blocking gaps           | +25% (realized risk of not making it work) |
| K3       | Vendor concentration; roadmap diverges from needs | +10% |
| K4       | Integration drag; owns 4 OSS components that each move | +15% |
| K5       | Compliance/risk failure; incident cost unbounded | +100% (not a comparable number) |
```

### 2.5 Budget defense memo

```markdown
# platform/budget-defense.md

## Recommendation
Invest in K4 (open-source assembly) for fiscal year 2027, with explicit
staffing for the single release-blocking remediation (C6 judge calibration)
and a budgeted quarterly re-evaluation of K3 (managed platform B) as the
field evolves.

## Rationale
1. K1 (build in-house) is the highest-weighted-capability choice but carries
   the largest upfront commitment (1,800k over 3 years, with +20% risk
   adjustment) and the longest time-to-first-value (6 months before a smoke
   test passes in CI).
2. K3 (managed platform B) is the second-highest-weighted choice but comes
   with vendor concentration and a non-trivial C8 integration cost. The
   3-year TCO after risk adjustment is competitive with K1 but exit cost
   adds 480k of future burden.
3. K4 (OSS assembly) scores 0.716 — 85% of K1's weighted score — at 76% of
   K1's TCO, with lower exit risk (we own the formats) and a single release-
   blocking remediation (C6).
4. K2 (managed platform A) and K5 (status quo) are dominated on both
   weighted score and TCO after risk adjustment; both are formally rejected.

## Alternatives rejected and why
- K1 is rejected for FY27 but not for FY28. If the K4 remediation of C6 is
  not satisfactory by end of Q2 FY28, the organization commits to re-opening
  the K1-vs-K3 decision with a new matrix.
- K3 is rejected for FY27 on exit-cost concerns; it is retained as a
  quarterly watchlist candidate in case its C8 and C11 roadmap closes the
  blocking-gap on terms better than our K4 remediation can.

## Assumptions
- Internal engineering rate $240k/year/eng (loaded).
- Eval volume grows 3x over 3 years.
- Managed-platform license pricing grows ~15%/year (stated in RFPs).
- The regulatory profile (ex-03) does not flip from non-high-risk to high-
  risk; if it does, the compliance-evidence capability (C11) jumps in
  weight, which materially affects K2 and K4's remediation costs.

## Risks
- OSS component churn: 4 components with 4 upstreams; if any abandons its
  AI/eval focus, we own the replacement.
- Judge calibration (C6) is an area under active research; our remediation
  plan assumes an internal 6-eng-month build, which could be shortened by
  an incoming OSS release or lengthened by an unmet research need.
- Internal hiring risk: the plan requires 1.5 platform engineers in
  steady-state; a failed hire delays by a quarter.

## Revisit trigger
This recommendation is revisited:
- At the end of each fiscal half.
- On any material change to the regulatory classification (see
  [exercise-03](../exercise-03-regulatory-mapping-rmf-iso-eu-ai-act/SOLUTION.md)).
- On any incident or missed SLO caused by the eval platform.
- On a managed-platform price change > 20% or vendor acquisition.

## Approvers
VP Eng (budget owner); Head of Model Eval; Head of ML Responsibility.
```

## 3. Validation steps

1. **Weight sign-off precedes scoring.** `git log platform/capabilities.md` shows a commit with the signed weights dated before the first commit of `platform/matrix.yml`. Weights changed after a scoring commit fail the lint and require an explicit re-sign-off commit with reason.
2. **Every capability has a sibling-module pointer.** `scripts/check_cap_refs.py platform/capabilities.md` verifies each row's reference resolves to an existing module.
3. **Every candidate scores every capability.** `scripts/check_matrix.py platform/matrix.yml` fails if any (cap × candidate) cell is missing. `null` is acceptable only for explicitly-marked n/a cells with a `why`.
4. **Status quo (K5) is present.** The lint enforces: the candidate list includes a `status_quo: true` entry. A matrix without the do-nothing option is a matrix with an invisible preferred answer.
5. **Weighted-sum arithmetic is reproducible.** `scripts/weighted_sum.py platform/matrix.yml` recomputes the totals; the recomputed values match the memo.
6. **Blocking gaps are enumerated explicitly.** For every candidate, the memo names the set of (capability, score) pairs where weight = 3 and score ≤ 1. No hidden blocking gaps.
7. **TCO model declares assumptions.** `platform/tco.md` has a section titled "Assumptions" naming the internal eng rate, the horizon, the growth assumption, and the exit-cost model. A TCO with no assumptions section fails the lint.
8. **Sensitivity analysis is present.** The TCO table is paired with a sensitivity table varying at least the growth assumption. A TCO with a single point estimate is flagged.
9. **Exit cost is modeled, not implicit.** For every managed-platform candidate, a non-zero exit cost appears. A "we will never leave" posture is not a valid budget defense.
10. **Approvers are named.** The memo names approvers by role; the approvals are recorded in the registry's alias-move audit when `platform/budget-defense@prod` is tagged.
11. **Revisit trigger is concrete.** Trigger conditions are enumerable events (a date, a classification change, a price delta, an incident), not "we will revisit periodically."
12. **No sunk-cost bias in rejection reasoning.** Rejected candidates are rejected on current analysis; language like "we already spent 6 months evaluating this" is a flag in review.

## 4. Rubric or review checklist

Scored out of 12. The rubric rewards the matrix being **a committed, auditable argument** — not a vendor-selection worksheet.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Capabilities (not vendors) are the rows; weights signed off before scoring | 2 | `capabilities.md` has 10+ capability rows with weights; sign-off commit precedes the first `matrix.yml` scoring commit. |
| R2 | "Status quo" is a real candidate column with its own score and TCO | 1 | K5 (or equivalent) is present and dominated candidates are explicitly rejected. |
| R3 | Each cell has a one-line justification; no bare numeric scores | 2 | `check_matrix.py` enforces non-empty `why` on every non-n/a cell. |
| R4 | Blocking-gap analysis names (cap, score) pairs for weight-3 capabilities ≤ score 1 | 2 | Memo section titled "Blocking gaps" enumerates them per candidate. |
| R5 | Three-year TCO with per-line breakdown (license, integration, remediation, ops, compliance, exit) | 2 | `tco.md` has a per-line table; totals match the memo. |
| R6 | Sensitivity analysis varies at least one assumption; risk-adjusted TCO is reported | 1 | Sensitivity table exists; adjustment percentages are declared. |
| R7 | Budget defense memo names recommendation, rejected alternatives with reasoning, assumptions, risks, revisit trigger | 1 | `budget-defense.md` has all five sections; each is substantive. |
| R8 | Vendor-security capability is scored and included in managed-platform candidates | 1 | C12 (or equivalent) is present and scored for K2/K3. |

**Passing bar:** 9 / 12. R1 and R4 are non-negotiable — a matrix that leads with vendors or hides blocking gaps is not a defensible decision. R5 is the next most-commonly weak — a TCO with license-only columns is a vendor comparison, not a cost model.

Reviewer checklist:

- [ ] Weights are signed off by the budget owner + key stakeholders before scoring.
- [ ] Rows are capabilities, not vendors. Columns include "status quo."
- [ ] Every cell has a numeric score + one-line justification.
- [ ] Weighted totals are reproducible by script.
- [ ] Blocking-gap analysis is explicit per candidate (weight-3 ≤ score 1).
- [ ] TCO model has per-line breakdown + sensitivity + risk adjustment + exit cost.
- [ ] Budget-defense memo names rejected alternatives and their reasons.
- [ ] Revisit triggers are concrete events, not "periodically."
- [ ] Vendor-security capability (SOC 2, data residency, sub-processors) is scored.

## 5. Common mistakes

- **Vendors as rows.** A matrix whose rows are "Vendor A, Vendor B, Vendor C" and columns are "cost, features, support" has no exposed value system; the comparison optimizes for the vendors' marketing axes. Capabilities first; weights first; scores last.
- **Status quo invisible.** "Build vs. buy" implies the decision must be made; sometimes the honest answer is "keep the notebooks running for six more months while hiring a platform engineer." Include status quo as a candidate; let it defend itself.
- **No sign-off on weights.** Weights adjusted after seeing scores is how a matrix produces whatever answer the author already preferred. Sign off weights in a dated commit before any scoring.
- **Sticker-price comparison.** "The license is $90k/yr, cheaper than three engineers" ignores integration, ongoing ops, exit, and compliance costs. Model the TCO.
- **No exit cost.** A "we will never leave" posture assumes eternal product-vendor alignment. Model the exit cost at the horizon of the decision.
- **One-point TCO.** A single estimate is not a budget defense; it is a guess. Sensitivity analysis on growth, on headcount, on license trajectory — at minimum one.
- **Weighted score as the answer.** The weighted sum is a signal, not a decision. A candidate that beats on weighted sum but has a release-blocking gap is not the pick; the blocking-gap analysis is co-equal.
- **Burying blocking gaps in a long "features gap" paragraph.** A reader scanning the memo sees a 0.75 weighted score and concludes the candidate is fine; the "candidate cannot satisfy six release-blocking capabilities without a 3-engineer remediation project" is buried in prose. Make blocking gaps a titled section.
- **Vendor-security ignored.** A managed-platform candidate is a new supply-chain dependency. SOC 2, data residency, sub-processor disclosure, incident-notification SLAs are all real columns, not footnotes.
- **Compliance evidence retention treated as vendor's problem.** The EU AI Act Art. 12 record-keeping obligation is the deployer's obligation, not the vendor's; if the vendor cannot retain evidence in a form the deployer can audit, the deployer must either build the retention externally or pick a different vendor. See [exercise-03](../exercise-03-regulatory-mapping-rmf-iso-eu-ai-act/SOLUTION.md).
- **"We already spent 6 months on this vendor" as a reason to pick them.** Sunk cost. Score on current information; the sunk time is not recoverable either way.
- **Revisit trigger is "periodically."** The field moves quarters. Concrete triggers: classification change; price delta > 20%; missed SLO caused by the platform; vendor acquisition; OSS component abandoned. Named events with named owners.
- **"Build" without a staffing plan.** "Build in-house" without an explicit 3-engineer, 18-month plan is a wish. The TCO model must show the staffing.
- **No rejected alternatives.** A memo that only defends the recommendation looks one-sided; a memo that names two rejected candidates with reasons passes budget review faster. Say what you considered and why it did not win.
- **Approvers are individuals.** Individuals rotate; the decision survives them. Approvers are roles: VP Eng, Head of ML Responsibility, Head of Model Eval. Record the role; log the individual's signature at approval time.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `GOVERN` function asks for "documented policies, processes, and roles for AI risk management with assigned accountabilities, informed by cost and risk trade-offs across the lifecycle." The capability inventory, weighted matrix, and budget defense memo are the operationalization — the cost/risk trade-off is made explicit, signed off, and refreshed on triggers.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML06 AI Supply Chain Attacks** is why vendor security is a scored capability — a managed platform is a supply-chain dependency with its own attack surface. **ML09 Output Integrity Attacks** motivates capability C11 (compliance evidence retention with integrity guarantees); evidence a vendor can edit in-place is not evidence.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0010 ML Supply Chain Compromise` is the threat model the vendor-security row (C12) defends against; sub-processor disclosure, SOC 2 coverage, and data-residency selection are the scored controls. `AML.T0005 Deliver Model via Publicly Available Service` frames the compliance-evidence-retention capability (C11) — a managed platform's audit log must be retrievable by the deployer to satisfy their own regulatory obligations, not just the vendor's.

<!-- Local exercise context: K2 and K3 are placeholder managed platforms; in a real procurement cycle the organization would name specific vendors and license tiers. The weights (1/2/3) and the TCO figures ($240k/eng, 3-year horizon, 15%/yr license growth, 20–30% risk adjustments) are illustrative defaults suited to a mid-sized engineering organization; a larger or smaller org would size differently. The recommendation (K4 for FY27, with K3 on watchlist) is the outcome of this worked example, not a general recommendation — organizations will produce different winners depending on their capability weights, regulatory profile, and existing engineering investment. Sibling exercises: the capability list (rows C1–C11) is populated from [mod-109](../../mod-109-safety-and-red-team-eval/README.md), [mod-110](../../mod-110-production-eval-regression/README.md), [mod-111](../../mod-111-eval-platform-engineering/README.md), and [exercise-01](../exercise-01-release-gate-plan-for-a-product/SOLUTION.md); the compliance-evidence-retention capability (C11) is specified in [exercise-03](../exercise-03-regulatory-mapping-rmf-iso-eu-ai-act/SOLUTION.md); the model card that documents the resulting system's eval evidence is [exercise-02](../exercise-02-model-card-from-eval-evidence/SOLUTION.md). -->
