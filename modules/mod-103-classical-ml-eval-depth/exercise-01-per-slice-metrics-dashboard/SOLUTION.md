# exercise-01 — Per-Slice Metrics Dashboard — Solution

## 1. Solution overview

The exercise asks the learner to turn an aggregate classification report into a **per-slice metrics dashboard**: one row per slice, one column per metric, with enough statistical honesty that a reviewer can tell whether a cross-slice gap is a real quality problem or sampling noise.

The reference answer has four deliverables:

1. A **slice taxonomy** — the slices the dashboard tracks, why each is on the list, and how the slice is defined from raw features.
2. A **metric set per slice** — primary metric, secondary metrics, and the sample-size floor below which the row is suppressed.
3. A **dashboard layout** — a single table a human can scan in under a minute, plus the drill-downs that back each cell.
4. An **alerting rule set** — the conditions under which a slice row triggers a gate, with the written policy for what the team does next.

This maps cleanly to the NIST AI RMF `MEASURE` function, which calls for metrics that are decomposed across the "context of use" — populations, deployment conditions, and known failure modes — rather than a single aggregate ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10 **ML08 Model Skewing**: slicing surfaces when a subgroup's inputs are degrading the model without moving the overall number, which is exactly what skewing attacks exploit ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS's `Discover ML Model Family` and `Evade ML Model` techniques describe adversaries probing where the model is weak — a per-slice dashboard tells defenders the same thing first ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Implementation

### 2.1 Slice taxonomy

Every slice on the dashboard is one of four kinds. Mixing kinds in a single list is fine — labeling them is not optional.

| Kind | Example slices | Why it is on the dashboard |
|---|---|---|
| **Demographic** | geography, age bucket, language, device class | Fairness and representational harm (see exercise-04). These slices often appear in a regulatory audit even if they are not a top business driver. |
| **Business** | top-10 customers, premium tier, high-ARPU segment | A regression on these slices is a revenue incident even if the aggregate is flat. |
| **Operational** | input length bucket, modality, time-of-day, upstream pipeline version | Known failure modes. These are the slices where the model's input distribution has shifted at some point in the past. |
| **Adversarial** | known-attack templates, canary items, prompt-injection probes | Skewing / evasion surface (ML08, ATLAS). A silent regression here is a security event, not a quality one. |

Rule: every slice has an **owner** named on the dashboard. A slice without an owner is decoration — nobody will act on a regression.

Definition of a slice is a committed function from the eval row to a boolean, not a free-text filter. A learner-grade schema:

```yaml
# slices.yaml
- slice_id: lang_es
  kind: demographic
  owner: "@localization-team"
  definition:
    language_code_in: ["es", "es-AR", "es-ES", "es-MX"]
  min_samples_for_display: 300
  primary_metric: f1
  secondary_metrics: [precision, recall, auroc, ece]
  gate: "f1 >= aggregate_f1 - 0.03 OR n < 300"
  rationale: "Spanish inputs regressed twice in 2025; keep on the dashboard until two clean quarters."
```

### 2.2 Metric set per slice

Pick a **primary metric** per slice (the thing a gate fires on) and keep the secondary metrics around as context so a reviewer can tell *which* kind of failure is happening.

Defaults for a binary classifier:

- Primary: `F1` or `AUPRC` for imbalanced slices; `accuracy` is acceptable only when prevalence is near 0.5 and both errors have similar cost.
- Secondary: `precision`, `recall`, `AUROC`, `AUPRC`, `ECE` (see exercise-02), `operating-point threshold` (see exercise-03), and prevalence.
- Diagnostic: confusion-matrix cells as counts, not rates — rates on a 40-item slice are misleading at a glance.

Every metric cell carries two numbers: the point estimate and a **95% confidence interval** computed from a bootstrap on the slice (10,000 resamples is cheap for all but the largest slices; a fixed random seed makes the CI reproducible). If the slice is under the `min_samples_for_display` floor, the dashboard shows `n/a (n=…, floor=…)` — not a tempting-but-wrong 100% accuracy on 4 items.

Sample-size floor is slice-dependent. A defensible default for a rate metric is "narrower than ±5 percentage points at the nominal rate," which under a normal approximation to the binomial gives roughly `n ≥ 400` for a rate near 50%, and larger `n` as you move away. Record the floor and the method; do not hardcode a single magic number.

### 2.3 Dashboard layout

One scannable table, with one row per slice and one column per metric. Sort order matters: put the **gate** column first, so a reviewer sees red before they see numbers.

```
┌──────────────────────┬───────┬─────┬────────┬─────────┬────────┬──────┬────────┬────────┐
│ slice                │ gate  │  n  │ prev.  │ F1      │ Prec.  │ Rec. │ AUPRC  │ ECE    │
├──────────────────────┼───────┼─────┼────────┼─────────┼────────┼──────┼────────┼────────┤
│ all (aggregate)      │  OK   │74312│ 0.12   │ 0.81 (±.004) │ 0.79 │ 0.84 │ 0.88  │ 0.021 │
│ lang_es              │  OK   │ 4812│ 0.14   │ 0.79 (±.012) │ 0.77 │ 0.81 │ 0.86  │ 0.028 │
│ lang_zh              │ ⚠REG  │  612│ 0.10   │ 0.70 (±.038) │ 0.68 │ 0.73 │ 0.78  │ 0.067 │
│ mobile_web           │  OK   │18422│ 0.11   │ 0.80 (±.006) │ 0.78 │ 0.82 │ 0.87  │ 0.023 │
│ top10_customers      │  OK   │ 2104│ 0.19   │ 0.83 (±.018) │ 0.84 │ 0.82 │ 0.90  │ 0.019 │
│ input_len>=1024      │  ⚠CAL │  987│ 0.09   │ 0.78 (±.028) │ 0.77 │ 0.79 │ 0.85  │ 0.093 │
│ canary_attack_v3     │  🚨SEC│  180│ 1.00   │ 0.42 (±.072) │ 0.95 │ 0.27 │ 0.61  │  —     │
│ night_batch_jobs     │ n/a   │  214│ 0.08   │ — (n<300)     │ —    │ —    │ —      │ —      │
└──────────────────────┴───────┴─────┴────────┴─────────┴────────┴──────┴────────┴────────┘
```

Drill-downs live one click (or `drill:` link) away from each row:

- Confusion matrix with raw counts.
- Error table with the first 50 misclassified items (hash-identified, not raw text, if the data is sensitive).
- Historical sparkline over the last `k` eval runs for the primary metric and ECE.
- Reliability diagram for the slice (see exercise-02).

### 2.4 Alerting rules

Three gate kinds. Only three — more than that and reviewers tune out.

- **REG (regression).** Primary metric for this slice is more than `Δ` below the aggregate or the previous blessed run, where `Δ` is slice-specific and committed in `slices.yaml`. Non-overlapping CIs between runs is the stricter form.
- **CAL (calibration).** ECE for this slice is above its documented ceiling (see exercise-02). A slice can be at full accuracy but miscalibrated; this gate catches that.
- **SEC (security).** Any adversarial / canary slice has moved. Canary slices do not need a `Δ`; any drop below the committed floor is an event. This is the ML08 skewing / ATLAS evasion signal.

Every gate fire is a row on a human-readable ticket with: slice, metric, prior value, current value, CI, and owner. No silent email summaries — those get filtered.

### 2.5 Reference layout on disk

```
dashboards/
  slices.yaml                     # slice definitions + gates
  metrics_by_slice.parquet        # one row per (slice, eval_run), cached
  renderer.py                     # table + sparkline generator
  gates.py                        # gate rule engine, reads slices.yaml
  reports/
    2026-11-13.md                 # current run
    2026-10-30.md                 # prior blessed run (for Δ comparison)
```

The dashboard is **not** a notebook. Notebooks hide the computation; a committed renderer with pinned dependencies is the control.

## 3. Validation steps

1. **Slice-coverage check.** Sum the sample counts across the dashboard's slices for a *partitioning* subset of the taxonomy (e.g. language codes) and confirm it equals the aggregate `n`. A slice taxonomy that doesn't cover the population is lying by omission.
2. **Determinism check.** Re-run the dashboard twice on the same eval artifact with the same seeds; every cell must be byte-identical. If CIs move, the bootstrap seed is unpinned.
3. **Floor-suppression check.** Add a synthetic slice with `n = floor - 1`. The row must render `n/a`, not a point estimate.
4. **Regression dry-run.** Replay last quarter's blessed eval and confirm the gate engine reproduces the alerts that were actually filed. If it does not, either the historical alerts were wrong or the gate rules have drifted from the written policy.
5. **Adversarial slice ping.** Flip the canary slice label on 5% of items (simulating the attack pattern). The SEC gate must fire. If it does not, the canary slice is cosmetic.
6. **Owner reachability.** For every slice with a gate, confirm the owner alias resolves to a reachable on-call rotation or team. A gate with no owner is a decoration.

## 4. Rubric

Scored out of 10. The rubric rewards the dashboard being *gate-capable*, not merely rendered.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Slice taxonomy is committed and labeled by kind | 2 | `slices.yaml` lists demographic, business, operational, and at least one adversarial slice, each with a kind tag and an owner. |
| R2 | Slice definitions are code, not free-text filters | 1 | Each slice is a committed predicate over schema fields; rerunning the renderer reproduces the slice membership. |
| R3 | Primary metric is appropriate for prevalence | 1 | Imbalanced slices use F1 or AUPRC; accuracy is used only where prevalence is near 0.5 with symmetric costs. |
| R4 | Every cell carries a 95% CI and the slice `n` | 1 | Bootstrap config is pinned; sample size appears on every row. |
| R5 | Sample-size floor suppresses under-powered rows | 1 | `n < floor` rows render `n/a` with the floor cited, not a misleading point estimate. |
| R6 | Gate rules are machine-executable and documented | 2 | REG, CAL, and SEC gates fire deterministically from the committed thresholds; each has a policy for what the team does when it fires. |
| R7 | Drill-downs reproduce the gate decision | 1 | A reviewer can go from a red cell to the misclassified items, confusion matrix, and reliability diagram without re-running the pipeline. |
| R8 | An adversarial / canary slice is on the dashboard | 1 | At least one slice exists explicitly to catch skewing or evasion, with a SEC gate. |

**Passing bar:** 7 / 10. Below that, the dashboard is a chart rather than a control.

### Review checklist (for a maintainer)

- [ ] Every slice has an owner alias that resolves to a real person or rotation.
- [ ] No row shows a rate on fewer than `min_samples_for_display` items.
- [ ] CIs are present for every point estimate; the bootstrap seed is committed.
- [ ] At least one gate has fired historically and been resolved — the dashboard is not a gate that never trips.
- [ ] The adversarial slice is documented well enough that a new engineer understands what a drop means.
- [ ] The aggregate row is **not** removed when an individual slice regresses — it is still the headline.

## 5. Common mistakes

- **Reporting only the aggregate.** The aggregate hides slice regressions that cancel in the mean. If the dashboard has only the headline number, it is not a per-slice dashboard.
- **Point estimates with no CI.** A 2-point drop on a 40-item slice is noise. Without CIs the dashboard rewards over-reaction and under-reaction in equal measure.
- **Letting a small slice render anyway.** "Accuracy 100% (n=4)" is the single most common mistake. Suppress or label clearly.
- **Free-text filters as slice definitions.** "customers in big markets" isn't a definition; `country_code in ("US","GB",…)` is.
- **One metric per slice, no secondary context.** A slice can crash precision while recall holds, and the primary F1 barely moves — you need the secondaries to see what broke.
- **No calibration column.** A slice can be at full accuracy but badly miscalibrated; that is a shipping risk the dashboard should surface alongside accuracy (see exercise-02).
- **Missing adversarial slice.** If nothing on the dashboard tracks the attack surface, the eval cannot detect ML08 / ATLAS evasion as a regression.
- **No ownership.** A gate without an owner is a gate that never gets resolved. The dashboard quietly degrades into noise.
- **Treating the slice list as permanent.** Slices earn their place on the dashboard; a slice with no action for N quarters should be rotated out so reviewers keep paying attention to the rest.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function expects metrics decomposed across the context of use (populations, operational conditions, and known failure modes), which is what a per-slice dashboard materializes.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML08 Model Skewing is the adversarial version of the drift that per-slice metrics are designed to surface; ML04 Membership Inference is a reminder not to leak raw per-item content in drill-downs.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Discover ML Model Family` and `Evade ML Model` describe adversaries probing where the model is weakest; the adversarial slices on the dashboard are the defender's version of the same measurement.

<!-- Local exercise context: specific slice names (lang_es, top10_customers, canary_attack_v3) and the ±5pp sample-size floor are illustrative defaults. Real slice lists and floors must be derived from the deployment's actual population and risk model, not from this worked example. -->
