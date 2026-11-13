# exercise-04 — Fairness Measurement Audit — Solution

## 1. Solution overview

The exercise asks the learner to **design and run a fairness measurement audit** on a classifier — choose the fairness criteria appropriate to the use case, measure them per group, surface the tradeoffs that classical results prove are unavoidable, and produce a decision record a reviewer can act on. "Fairness" is not a single metric; the audit's job is to pick the right one, measure it honestly, and be explicit about what it does *not* protect against.

The reference answer has five parts:

1. A **harm scoping** step — the use case, the groups at risk, the type of harm (allocative vs representational), and what "fair" is supposed to mean here.
2. A **metric selection** step — which group-fairness criteria apply, and why the others are off the table.
3. A **measurement** step — per-group rates with CIs, intersectional breakdowns, and sample-size floors.
4. A **tradeoff and decision** step — making the inherent conflicts between fairness definitions explicit and choosing where to stand.
5. A **mitigation and monitoring** step — what to change (data, model, threshold, post-processing), and the gate that catches regression.

This exercise is anchored in the NIST AI RMF `MEASURE` and `MANAGE` functions: `MEASURE` because the audit is a committed measurement protocol tied to the context of use, and `MANAGE` because a fairness finding converts into a decision record with named owners, timelines, and rollback paths ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial surface comes from OWASP ML Top 10 **ML08 Model Skewing** — an attacker who skews the training distribution against a group produces exactly the harm the audit is designed to detect, and the audit is the detection control ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS's `Discover ML Model Family` and `ML Model Poisoning` tactics describe adversaries probing group-specific weaknesses; fairness metrics are the defender's instrumented view of the same surface ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Implementation

### 2.1 Harm scoping

Fairness is only well-defined once you've written down *who* could be harmed and *how*. The reference answer opens with a one-page scoping doc.

```markdown
## Scoping — <system under audit>
- Decision: <which output of the model becomes a consequential action?>
- Decision kind: allocative (approves/denies something scarce) | representational (shapes attention, ranking, visibility)
- Groups at risk: <list, with how they are identified, and the lawful basis for having that attribute>
- Base rate dependency: does the ground-truth prevalence differ by group? Known sources: <citations>
- Reference harm: <specific harm to a member of each group if the model is wrong>
- Non-fairness controls already in place: <human review, appeal, policy override, etc.>
- Explicitly out of scope: <harms this audit will not detect — e.g. individual fairness, counterfactual fairness, procedural fairness>
```

Two scoping pitfalls this document has to resolve on paper:

- **Group definition.** If the attribute is self-reported, missing-at-random matters. If the attribute is inferred, the inference is itself auditable (and may be prohibited). Pick one, say which, and cite the policy or legal basis for having it.
- **Base rates.** Many fairness metrics behave very differently when the ground-truth prevalence differs by group — a fact that makes the trade-offs in §2.4 unavoidable. Scoping must record whether prevalence is believed equal across groups, and what evidence supports that belief.

### 2.2 Metric selection

Group-fairness metrics fall into three families. Most real audits require **at least one from two different families**, because any single metric can be gamed by a model that fails elsewhere.

| Family | Definition | What a learner-grade metric looks like | When it is appropriate |
|---|---|---|---|
| **Independence** (demographic parity) | `P(ŷ=1 | A=a)` equal across `a`. | Selection-rate ratio or difference per group. | Allocative decisions where equal opportunity to receive the allocation is the policy goal, and where disparate base rates are not accepted as an operational given. |
| **Separation** (equalized odds) | `P(ŷ=1 | Y=y, A=a)` equal across `a` for each `y`. | TPR and FPR per group; parity measured by difference or ratio. | Decisions where the cost of a false positive and false negative are large, and where the group distribution of true labels is accepted. |
| **Sufficiency** (calibration parity) | `P(Y=1 | Ŝ=s, A=a)` equal across `a` for each score `s`. | Reliability diagrams per group; per-group ECE (see exercise-02). | Decisions whose downstream pipeline uses the probability as a probability (routing, cost-sensitive thresholds, aggregated risk). |

The written selection must do three things:

1. Name the chosen family(ies) and the group-comparison statistic (difference or ratio, and an absolute or relative threshold).
2. Name the metrics it is **not** selecting and why. "We aren't measuring demographic parity because base rates genuinely differ and policy accepts that" is a complete answer; "we didn't think about it" is not.
3. Name a disparity ceiling per metric, consistent with the policy goal. For allocative decisions a "4/5" ratio rule has long been used as a conventional screen in US employment law; use what your deployment actually requires, cited in the audit.

### 2.3 Measurement protocol

Every metric in §2.2 is computed:

- **Per group**, with a 95% bootstrap CI.
- **Pairwise across groups**, as both difference and ratio.
- **Intersectionally**, on at least the two-way combinations of the protected attributes that scoping named. Single-attribute slicing hides the cases where the model fails on people at the intersection.
- **Over time**, so that today's eval slot is comparable to prior ones (otherwise a slow drift can look like a one-shot regression).

Minimum table in the report:

```
Metric: true positive rate (TPR) — equalized odds
                 n    TPR          95% CI       Δ vs. reference    Ratio vs. reference
group_a_women  2,104  0.78  (0.75, 0.81)       —                   —          (ref)
group_a_men    3,218  0.82  (0.79, 0.85)       +0.04               1.05×
group_b_women    412  0.69  (0.59, 0.78)       -0.09               0.88×  ← fails 0.9 floor
group_b_men      601  0.74  (0.66, 0.82)       -0.04               0.95×
group_a×age_60+  ...  ...   ...                ...                 ...
```

A row is rejected as evidence (not as a finding) if `n` is below the committed floor. "Insufficient data to measure" is a fairness finding too; it means the deployment should either collect more labels for that group or acknowledge that it cannot measure the harm.

Four measurement must-dos most learner solutions miss:

- **Confidence intervals.** A 4-point gap on `n=400` may not be a real gap.
- **Sign matters.** TPR can be high on group A while FPR is also high — equalized odds requires *both*. Report both and gate on the worse.
- **Prevalence drift.** A per-group prevalence drift can move the apparent fairness number without the model changing. Record the per-group label prevalence alongside the metric.
- **Missing attributes.** Items with missing group labels are their own bucket, not implicitly reassigned to the majority. Report them.

### 2.4 Tradeoffs

Classical results show that when the ground-truth prevalence differs across groups, three common fairness definitions — demographic parity, equalized odds, and calibration parity — cannot all hold simultaneously except in degenerate cases. The audit must:

1. **State which pair of criteria the deployment prioritizes**, and record the one it accepts giving up.
2. **Show the numeric cost** of that choice on the current model: if you prioritize calibration parity, show the equalized-odds gap that remains; if you prioritize equalized odds, show the calibration gap.
3. **Reference the policy owner** who chose. This is not an engineering decision.

A learner-grade worked tradeoff section:

```markdown
## Tradeoff decision
This system prioritizes **sufficiency (calibration parity)** because the downstream cost-sensitive threshold (see exercise-03) relies on scores being interpretable as probabilities at the same rate across groups. The accepted cost is a residual **separation gap** in false-positive rate, measured at 0.03 absolute at the chosen operating point. Policy owner: @policy-lead, decision date: 2026-11-13. Reviewed quarterly.
```

The point is not that the tradeoff disappears; the point is that it is made in writing, with a named owner.

### 2.5 Mitigation path

Mitigations are ordered by how far from the decision they land. Prefer upstream:

1. **Data.** Rebalance labels, collect more data for underrepresented groups, audit labels for bias, remove features that act as proxies without justification. Upstream fixes are durable; everything below is a patch.
2. **Model.** Re-train with a group-aware loss, add adversarial debiasing, or explicitly reweight. Record which was tried and the metric movement.
3. **Threshold.** Pick a per-group operating point (see exercise-03). This can close equalized-odds gaps at the cost of a different global threshold and may carry policy / legal implications in some jurisdictions — flag them in the record.
4. **Post-processing.** Re-rank, add a calibrator per group (see exercise-02), or use reject-option classification. Patchy; useful as a stopgap while upstream fixes are in flight.
5. **Decline the decision.** If no mitigation closes the gap to an acceptable floor, the correct action can be to not ship — or to route the affected items to human review.

Every mitigation has (a) the pre/post metric table, (b) a per-slice non-regression check (did we close one gap and open another?), and (c) an owner and timeline.

### 2.6 Minimal reference implementation

```python
# fairness.py
import numpy as np

def group_tpr_fpr(scores, y, A, threshold):
    out = {}
    yhat = scores >= threshold
    for a in np.unique(A):
        mask = A == a
        y_a, yhat_a = y[mask], yhat[mask]
        pos = y_a == 1
        neg = y_a == 0
        tpr = yhat_a[pos].mean() if pos.any() else np.nan
        fpr = yhat_a[neg].mean() if neg.any() else np.nan
        out[a] = {"n": int(mask.sum()), "n_pos": int(pos.sum()), "tpr": float(tpr), "fpr": float(fpr)}
    return out

def selection_rate(yhat, A):
    return {a: float((yhat[A == a]).mean()) for a in np.unique(A)}

def bootstrap_gap(fn, scores, y, A, threshold, ref, n_boot=10_000, seed=0):
    rng = np.random.default_rng(seed)
    n = len(scores)
    gaps = []
    for _ in range(n_boot):
        ix = rng.integers(0, n, n)
        r = fn(scores[ix], y[ix], A[ix], threshold)
        if ref in r:
            tprs = {a: r[a]["tpr"] for a in r}
            gaps.append(max(tprs.values()) - tprs[ref])
    gaps = np.array(gaps)
    return float(np.quantile(gaps, 0.025)), float(np.quantile(gaps, 0.975))
```

## 3. Validation steps

1. **Scoping completeness.** The scoping doc names the groups, the harm, and what is explicitly out of scope. A scoping doc that silently excludes a group the deployment serves is itself a finding.
2. **Metric-family diversity.** At least one metric from a second family is in the report. If only separation metrics are measured and the downstream pipeline uses the probability, the audit has missed calibration parity.
3. **Base-rate honesty.** Per-group `P(Y=1)` is reported. An equalized-odds "pass" on groups with wildly different prevalence may still carry a demographic-parity gap that policy cares about — the reader needs both numbers in front of them.
4. **Intersectional breakdown.** At least two-way slices are computed; a row with `n` below the floor is labeled "insufficient data," not silently dropped.
5. **Tradeoff decision is written down.** The audit names a policy owner and the accepted gap in the metric it chose to give up. "We are fair" with no gap table is a red flag.
6. **Mitigation pre/post.** If any mitigation was applied, the report has a before-and-after table that includes per-slice non-regression. A mitigation that closes gap A and opens gap B must be rejected or justified.
7. **Adversarial check.** Flip 5% of a protected group's labels (simulating label-flip poisoning). Confirm the fairness gate moves — this is the ML08 skewing detection check.
8. **Reproducibility.** The whole audit re-runs from the committed artifact in a clean environment and produces byte-identical tables.

## 4. Rubric

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Scoping doc names groups, harm, and out-of-scope harms | 2 | Allocative vs representational is labeled; lawful basis for the group attribute is cited; omitted fairness notions are named. |
| R2 | Metrics from at least two families are measured | 2 | Independence, separation, or sufficiency — at least two — each with a disparity ceiling cited to a policy or regulation. |
| R3 | Per-group metrics have CIs and `n` is reported | 1 | Bootstrap seed committed; CIs on every rate. |
| R4 | Intersectional breakdowns computed | 1 | At least two-way interactions on the protected attributes; under-powered cells labeled, not dropped. |
| R5 | Tradeoff is explicit, with the numeric cost of the chosen priority | 2 | The pair of criteria prioritized is named; the gap in the sacrificed criterion is quantified; the policy owner is on record. |
| R6 | Mitigation plan with pre/post and non-regression | 1 | If mitigation is applied, there is a before-and-after per-slice table. If no mitigation is applied, the report says why. |
| R7 | Fairness gate in the dashboard | 1 | A gate fires when any protected-group metric regresses beyond its ceiling or when disparity widens; owner is named. |

**Passing bar:** 7 / 10.

### Review checklist (for a maintainer)

- [ ] Scoping doc exists and names the groups and harms.
- [ ] At least two metric families are measured.
- [ ] Prevalence by group is in the report alongside the fairness metric.
- [ ] Intersectional breakdowns are in the report; small cells are labeled, not hidden.
- [ ] The accepted tradeoff is written down, with a policy owner.
- [ ] A fairness gate exists on the dashboard and has an owner.
- [ ] The report calls out what the audit *does not* detect (individual, counterfactual, procedural fairness — whichever is out of scope).

## 5. Common mistakes

- **Reporting demographic parity in isolation.** Equal selection rates can mask different error rates across groups. Report with a separation metric to see what you are losing.
- **Ignoring base rates.** A pass on equalized odds can coexist with large demographic-parity gaps when prevalence differs across groups. Readers need the base-rate column to interpret the audit.
- **Only one-way slicing.** Group-level parity can hide intersectional failures; the audit has to go at least one level deeper.
- **Dropping small cells silently.** A cell with `n` below the floor is itself a finding (we cannot measure this group's experience). Dropping it is worse than reporting it as insufficient.
- **Treating the tradeoff as an engineering decision.** Choosing which fairness criterion to prioritize is a policy decision. Name the owner.
- **Mitigating one gap, opening another.** A per-group threshold can close an equalized-odds gap while opening a calibration gap. Pre/post with all metrics prevents this.
- **No adversarial slice.** ML08 Model Skewing produces exactly the signatures the audit is designed to detect; the audit should include a simulated-skew check so it catches that case rather than only fully-organic drift.
- **One-shot measurement.** Fairness drifts; without a gate on the dashboard, the next regression ships silently.
- **Scoping that excludes the groups most at risk.** Scoping that lists only the groups the system already serves well is worse than no scoping at all.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function expects metrics decomposed by group and context of use; the `MANAGE` function turns a fairness finding into a decision record with named owners and remediation plans. Pair this exercise with its scoping doc under the `MAP` function as well.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML08 Model Skewing is the adversarial manifestation of the harms the audit detects; ML04 Membership Inference is the reason protected-attribute data has to be handled with care in audit artifacts.
- MITRE ATLAS — <https://atlas.mitre.org/>. The `Discover ML Model Family` and `ML Model Poisoning` tactics describe adversaries looking for and exploiting group-specific weaknesses; a fairness gate on the dashboard is the defender's version of the same measurement.

<!-- Local exercise context: the TPR/FPR table, the chosen "sufficiency over separation" tradeoff, and the 4/5 conventional ratio floor are illustrative. Real metric choices and thresholds must be derived from the specific deployment's policy, legal context, and the harm scoping done in §2.1. -->
