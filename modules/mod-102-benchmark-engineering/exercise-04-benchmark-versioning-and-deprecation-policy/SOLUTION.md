# exercise-04 — Benchmark Versioning and Deprecation Policy — Solution

## 1. Solution overview

The exercise asks the learner to write — and defend — a **versioning and deprecation policy** for a benchmark that other teams depend on. The reference answer has four pieces:

1. A **semantic versioning rule** that maps benchmark changes to MAJOR / MINOR / PATCH and makes "which changes are breaking" machine-checkable.
2. A **changelog + release-notes template** that captures what a downstream consumer needs to decide whether to upgrade.
3. A **deprecation policy** — how long an old version is still supported, how deprecation is announced, when it is removed.
4. A **compatibility test suite** that the benchmark itself runs on every version bump so the version number cannot drift from the actual change.

The exercise maps to the NIST AI RMF `GOVERN` function, which asks for documented policies for third-party and shared artifacts, and to `MANAGE`, which asks for lifecycle controls on measurement artifacts ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). Loose versioning is also the attack surface behind **ML06 Corrupted Packages** on the OWASP ML Top 10 and the **Supply Chain Compromise** tactic on MITRE ATLAS — a benchmark that silently changes under its own version string is indistinguishable, from the consumer side, from a swap attack ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/); [MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Implementation

### 2.1 Versioning rule — benchmark-specific SemVer

SemVer 2.0 is the base ([semver.org](https://semver.org/)). The benchmark-specific question is: *what does "breaking" mean for a benchmark?* The rule the reference answer uses:

**Breaking (MAJOR bump): any change that makes scores on vN not comparable to scores on vN−1.** Concretely:

- Adding, removing, or re-splitting items (train / dev / test movement).
- Changing the prompt template, target format, or scoring key for any item.
- Tightening or loosening the metric definition (e.g. switching exact-match → normalized exact-match).
- Changing the decontamination policy in a way that moves items into or out of the scored set.
- Any change to the license that narrows permitted uses.

**Non-breaking feature (MINOR bump): changes that extend the benchmark without invalidating prior scores.** Concretely:

- Adding a new *optional* slice / split alongside the existing one.
- Adding a new companion metric reported next to the headline score.
- Expanding documentation, metadata, or provenance (no items change).
- Adding a new, backward-compatible fixture file.

**Patch (PATCH bump): corrections that do not move scores.** Concretely:

- Typo fixes in documentation.
- Metadata fixes (author names, URLs) that do not alter any item or its scoring.
- Adding re-derivation scripts or non-scored fixtures.

The hard rule: if a change moves the headline score for *any* fixed-weights model by more than the benchmark's committed noise floor, it is MAJOR, not MINOR.

#### Pre-1.0 and 0.y.z

Per SemVer, 0.y.z is explicit "not stable." Benchmarks in pilot use `0.y.z` and may break on any version. Promote to 1.0.0 the first time a model's score is used to make a release decision outside the authoring team.

#### Build metadata and pre-release

- `1.4.0-rc.1` for release candidates distributed for consumer dry-runs before a MAJOR.
- `1.4.0+regen20261101` for build metadata (regeneration date, content hash) — build metadata must never change scores or disposition; if it does, that is a MAJOR.

### 2.2 Release manifest

Every release — MAJOR, MINOR, or PATCH — writes a single manifest that is the authoritative claim about the artifact.

```yaml
# RELEASE.yaml
benchmark: factuality-qa
version: "2.1.0"
previous_version: "2.0.3"
released_on: "2026-11-11"
artifact:
  path: "dist/factuality-qa-2.1.0.tar.gz"
  sha256: "<sha256 of the artifact>"
  item_count: 1915
changelog:
  - type: "minor"
    summary: "Added `source_lang` metadata field to every item."
    affects_scoring: false
    affected_items: 1915
compatibility:
  scores_comparable_to_previous: true   # MUST be true for MINOR / PATCH
  reference_score_check:
    model: "ref-model-v3 (frozen)"
    previous_headline: 0.6421
    current_headline:  0.6418
    delta: -0.0003
    noise_floor: 0.0020
    verdict: "within noise floor"
support:
  this_version_supported_until: "2027-11-11"
  previous_version_deprecated_on: "2026-11-11"
  previous_version_removed_on: "2027-02-11"
```

Why each field:

- `sha256` + `item_count` let a consumer prove they are actually running the version they think they are.
- `scores_comparable_to_previous` must be `true` for MINOR / PATCH by definition. A MAJOR explicitly sets it `false` with a reason.
- `reference_score_check` is the empirical guardrail: a frozen reference model is scored on both the old and new version, and the delta is reported against the committed noise floor. If the delta exceeds the noise floor, the release is misclassified and must be re-cut as a MAJOR.
- Support windows are explicit timestamps, not "soon."

### 2.3 Deprecation policy

The reference policy, with the rationales:

1. **Advance notice.** A deprecation is announced at least **one release cycle** before the version is marked deprecated. For benchmarks on a quarterly cadence, that is roughly 90 days.
2. **Deprecated, not removed.** On the deprecation date, the version is marked `deprecated: true` in the release manifest and in the artifact landing page. Downloads keep working. New scores can still be submitted. Leaderboard labels change to "(v1.x, deprecated)."
3. **Removal window.** A deprecated version is kept downloadable for at least **90 days** after deprecation (so consumers have time to migrate). After removal, the artifact is kept in a cold archive — never permanently deleted — because old scores must remain reproducible.
4. **Score amnesty.** Scores recorded against a deprecated version are not retracted. The leaderboard shows the version each score was run against and does not mix scores across MAJORs on the headline axis.
5. **Security exception.** A MAJOR that fixes a **safety-relevant contamination** (eval items found in widely-used training corpora) or a **license defect** (an item the benchmark did not have the right to distribute) may skip the advance-notice window. In that case, the release note names the reason and the policy section "Security exception" lists the override justification.

A worked timeline for a MAJOR:

```
2026-11-11  v3.0.0-rc.1 published for consumer dry-run; v2.x notice: "v2.x will deprecate on 2027-02-11"
2027-02-11  v3.0.0 released; v2.x flagged deprecated
2027-05-11  v2.x removed from primary distribution (archived to cold store)
2027-11-11  v3.x support window ends unless renewed
```

### 2.4 Compatibility test suite

The policy is only as good as the tests that enforce it. Every release runs the following against the previous shipping version:

1. **Item-set diff.** Set difference on item IDs. For MINOR/PATCH, the diff must be empty (or a strict superset for MINOR when new *optional* items are added to an *optional* new slice). Any removal is MAJOR.
2. **Per-item scoring-key hash.** Hash the normalized scoring key for every shared item. Any change in any hash is MAJOR.
3. **Metric function hash.** Hash the metric function (source + dependencies). A change is MAJOR unless it is a refactor that is byte-identical in output on a committed regression fixture.
4. **Reference-model delta.** Score a committed frozen model on both versions. Delta must be within the committed noise floor for MINOR/PATCH. If it isn't, re-cut as MAJOR.
5. **Documentation-only diff.** For PATCH, the diff must touch only files under `docs/` or `metadata/` and must leave all of (1)–(4) unchanged.

The tests are a pre-commit or CI gate on the release PR. Failing a gate blocks the release *until the version bump is corrected*, not until the test is bypassed.

```python
# version_gate.py (sketch)
def classify_bump(prev, curr):
    if diff_item_set(prev, curr) \
       or diff_scoring_keys(prev, curr) \
       or diff_metric(prev, curr) \
       or abs(reference_delta(prev, curr)) > noise_floor():
        return "major"
    if added_optional_items(prev, curr) \
       or added_optional_metric(prev, curr):
        return "minor"
    if only_docs_or_metadata(prev, curr):
        return "patch"
    return "unknown"   # pipeline should refuse to release
```

Compared against the version string in `RELEASE.yaml`, mismatch fails the CI job.

## 3. Validation steps

1. **Classify a known change.** Given the diff between two committed releases, the gate must produce the same MAJOR / MINOR / PATCH label the release note claimed. Run this against the last three releases as a regression test.
2. **Noise-floor coverage.** The committed noise floor must be derivable from a bootstrap of the frozen reference model's scores across repeated runs — not a round number. Reviewer should be able to re-derive it.
3. **Deprecation timeline check.** For any version flagged `deprecated: true`, the manifest has an explicit removal date and an explicit archive path. "TBD" fails.
4. **Score-amnesty integrity.** Leaderboard rows carry the version they were scored against. Attempting to compare scores across a MAJOR without reconciliation must surface a warning.
5. **Reproducibility of deprecated scores.** Pick an archived release at random; verify that downloading, re-scoring the reference model, and recomputing the headline reproduces the recorded number within noise floor.
6. **Security-exception audit.** Any release that invoked the security exception must have a recorded reason under `support.exception_reason`. An empty field blocks publication.

## 4. Rubric

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | MAJOR / MINOR / PATCH rule is explicit and testable | 2 | Rule is written down; `version_gate.py` (or equivalent) exists and can be run on any diff. |
| R2 | RELEASE manifest has artifact hash, item count, previous version, dates | 1 | All fields present, no "TBD". |
| R3 | Reference-model delta check is committed | 2 | Noise floor is derived (not asserted), and the delta check runs on every bump. |
| R4 | Deprecation window and removal window are defined in time | 1 | Specific durations (e.g. 90 days), not "a while." |
| R5 | Deprecated versions remain downloadable through removal date | 1 | Policy says so; archive path exists. |
| R6 | Score amnesty / cross-MAJOR reconciliation is defined | 1 | Leaderboard records version per score; headline comparison across MAJORs is explicitly forbidden or reconciled. |
| R7 | Security-exception path exists and is bounded | 1 | Policy names the two or three reasons that justify skipping advance notice. |
| R8 | CI/gate blocks mislabeled bumps | 1 | Mislabeled bump (e.g. MINOR for an item removal) is rejected by the gate in a committed test. |

**Passing bar:** 7 / 10. R1 and R3 are mandatory — either failing drops the submission below passing regardless of total.

### Review checklist

- [ ] RELEASE.yaml present, machine-parseable, no "TBD".
- [ ] Artifact hash matches the dist tarball.
- [ ] Noise floor is derived from data, not stated.
- [ ] Reference-model delta reported for MINOR/PATCH.
- [ ] Deprecation and removal dates are real dates.
- [ ] Archive path exists (or is explicitly `archive-pending`).
- [ ] CI test rejects a hand-crafted mislabel.

## 5. Common mistakes

- **Treating "I renamed a file" as PATCH.** If the rename changes any scoring key, metric, or item ID, it is MAJOR. The gate has to decide, not the author.
- **Silent re-generation.** "Rebuilt the dataset from the same seed, same score" — still MAJOR unless the item IDs and scoring keys are byte-identical.
- **Noise floor by assertion.** Picking `0.001` because it feels tight. Derive the noise floor from repeated scoring of the same frozen model and commit the derivation.
- **Deprecation with no removal date.** "Deprecated indefinitely" is a trap. Pick a removal date and let the archive carry the long tail.
- **Deleting deprecated versions.** Old scores must remain reproducible. Archive, don't delete.
- **Cross-MAJOR leaderboard.** Showing v1.4.2 and v2.0.0 scores on the same axis invites bad comparisons. Either reconcile with a mapping function and show both, or split the leaderboard.
- **No security exception path, so the first incident has no process.** Write the exception path before you need it.
- **Build metadata that changes scores.** `+regen20261101` must not change any score. If it does, it is a MAJOR masquerading as a tag.

## 6. References

- Semantic Versioning 2.0.0 — <https://semver.org/>. The baseline rule set; this policy adds benchmark-specific definitions of "breaking."
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. `GOVERN` 1.2 (policies and procedures), `GOVERN` 6.1 (supplier / third-party artifact lifecycle), `MANAGE` 4.1 (ongoing monitoring of deployed measurement).
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML06 (Corrupted Packages) — a loosely versioned benchmark is a supply-chain risk.
- MITRE ATLAS — <https://atlas.mitre.org/>. Supply-chain compromise tactics; signed manifests and reproducible archives are the defensive posture.

<!-- Local exercise context: specific durations (90-day deprecation, 90-day removal window) are illustrative defaults. A learner's real policy should pick durations their consumers can meet and document the trade-off. -->
