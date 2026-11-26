# exercise-01 — Versioned Registry Design — Solution

## 1. Solution overview

An eval platform without a registry is a collection of CSVs in people's home directories. Two months in, `accuracy.py` in service A does not agree with `accuracy.py` in service B, `v1` of the dataset lives in three S3 buckets with three sort orders, and the judge prompt that produced last quarter's number is nowhere on disk. The registry's job is to be the **single addressable source** for every object an eval run consumes — datasets, metrics, judges, prompt templates, model configs, run configs — so that any report can be rerun six months later and produce a byte-identical number.

The design hinges on four non-negotiables:

- **Content-addressed storage.** The identity of a dataset version is the SHA-256 of its normalized contents, not a human-chosen tag. `datasets/billing-chats@sha256:7f3a...` is the real id; `billing-chats:v4` is a human alias that points to a SHA. Aliases move; SHAs do not.
- **Immutable versions, movable aliases.** Once a version is registered its bytes never change. If a typo is found you publish a new version; you do not edit `v4`. Aliases (`v4`, `prod`, `latest`) are mutable labels maintained in a separate table.
- **Explicit lineage.** Every artifact declares the artifacts it was derived from (dataset v4 was built from `raw-chats@sha256:...` via pipeline `redact@v2.1`). The registry is a DAG, not a flat list.
- **Semantic version policy per artifact type.** Breaking schema changes bump the major; adding an optional field bumps the minor; relabeling an item bumps the patch. The policy is written down and the registry rejects pushes that violate it.

The reference answer has five deliverables:

1. A **registry data model** (schema diagram + table DDL) covering artifacts, versions, aliases, lineage, and ACLs.
2. A **naming and versioning policy** (`docs/registry-policy.md`) that pins the URI grammar, the SemVer rules per artifact type, and the deprecation lifecycle.
3. A **reference client** (`registry.py`) with the five operations platform users actually call: `register`, `resolve`, `get`, `tag`, `deprecate`.
4. A **resolver service** (`resolver.py`) that turns a human URI (`datasets/billing-chats@v4`) into a pinned manifest (SHA, lineage, ACL check result) before any runner opens a byte.
5. A **governance surface** (`docs/review-gates.md`) — who can publish a dataset to `prod`, who can approve a judge prompt change, what triggers a deprecation window.

This maps directly to the NIST AI RMF `GOVERN` and `MAP` functions: `GOVERN` asks for "documented, enforced policies for data, model, and tool provenance across the lifecycle"; `MAP` asks that "artifacts, roles, and their relationships be enumerated" — a lineage DAG with owner metadata is the direct operationalization ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial lens is OWASP ML Top 10: **ML06 AI Supply Chain Attacks** is the registry's primary threat model (an unsigned dataset mutated in place silently rewires every downstream eval), and **ML02 Data Poisoning Attack** is why aliases must be auditable — a `prod` alias moved under the hood lets a poisoned version ride into every gated run ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0010 ML Supply Chain Compromise` and `AML.T0020 Poison Training Data` frame the registry as a defended control plane: the registry is where the chain of custody ends or breaks ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked design and implementation

### 2.1 URI grammar

Every artifact has one canonical URI. The resolver accepts three forms; all resolve to the same pinned SHA before any byte is read.

```
# Content-addressed (always resolvable, never ambiguous)
datasets/billing-chats@sha256:7f3a9c4e...
metrics/exact-match@sha256:1b2c...
judges/helpfulness-v2@sha256:ab...
prompts/chat-system@sha256:...

# Semantic version (resolves via alias table)
datasets/billing-chats@v4.2.1
judges/helpfulness-v2@v1.3.0

# Floating alias (resolves via alias table; audited)
datasets/billing-chats@prod
datasets/billing-chats@latest
judges/helpfulness-v2@staging
```

Rules the grammar enforces:

- **Artifact type is part of the URI, not inferred.** `billing-chats@v4` is not resolvable; the type disambiguates datasets from metrics (which could share a name).
- **No bare names.** A URI without `@...` is rejected at the resolver. Rerunnability depends on every URI pinning a version — a run manifest that says `datasets/billing-chats` is a time bomb.
- **Aliases are per-environment.** `prod`, `staging`, `canary` are reserved aliases with ACLs; `latest` is an optional convenience for development only, never permitted in a run manifest promoted beyond dev.

### 2.2 Data model

Five tables cover the registry. The schema is the committed contract; diagrams follow it.

```sql
-- Every registered artifact (dataset, metric, judge, prompt, model, run-config)
CREATE TABLE artifacts (
    artifact_id      TEXT PRIMARY KEY,              -- "datasets/billing-chats"
    artifact_type    TEXT NOT NULL,                 -- dataset|metric|judge|prompt|model|run_config
    owner_team       TEXT NOT NULL,                 -- routable team id
    created_at       TIMESTAMPTZ NOT NULL,
    description      TEXT,
    CHECK (artifact_type IN ('dataset','metric','judge','prompt','model','run_config'))
);

-- Immutable, content-addressed versions
CREATE TABLE versions (
    sha256           TEXT PRIMARY KEY,              -- hex content hash
    artifact_id      TEXT NOT NULL REFERENCES artifacts(artifact_id),
    semver           TEXT NOT NULL,                 -- "4.2.1"
    storage_uri      TEXT NOT NULL,                 -- s3://registry/datasets/.../7f3a....tar.zst
    size_bytes       BIGINT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    created_by       TEXT NOT NULL,                 -- principal id (audited)
    signing_key_id   TEXT,                          -- the signer; verified at publish
    metadata_json    JSONB NOT NULL,                -- type-specific manifest
    UNIQUE (artifact_id, semver)
);

-- Mutable labels pointing at versions; moves are audited
CREATE TABLE aliases (
    artifact_id      TEXT NOT NULL REFERENCES artifacts(artifact_id),
    alias            TEXT NOT NULL,                 -- "prod", "staging", "v4", "latest"
    sha256           TEXT NOT NULL REFERENCES versions(sha256),
    moved_at         TIMESTAMPTZ NOT NULL,
    moved_by         TEXT NOT NULL,
    reason           TEXT NOT NULL,                 -- free text; audited
    PRIMARY KEY (artifact_id, alias)
);

-- Full audit log of alias moves (append-only)
CREATE TABLE alias_history (
    id               BIGSERIAL PRIMARY KEY,
    artifact_id      TEXT NOT NULL,
    alias            TEXT NOT NULL,
    old_sha256       TEXT,                          -- NULL on first set
    new_sha256       TEXT NOT NULL,
    moved_at         TIMESTAMPTZ NOT NULL,
    moved_by         TEXT NOT NULL,
    reason           TEXT NOT NULL
);

-- Lineage DAG: this version was derived from these parents by this producer
CREATE TABLE lineage_edges (
    child_sha256     TEXT NOT NULL REFERENCES versions(sha256),
    parent_sha256    TEXT NOT NULL REFERENCES versions(sha256),
    producer_sha256  TEXT NOT NULL,                 -- the pipeline/tool version
    role             TEXT NOT NULL,                 -- "source", "redactor", "augmenter", ...
    PRIMARY KEY (child_sha256, parent_sha256, role)
);

-- Deprecations with an end-of-life horizon
CREATE TABLE deprecations (
    sha256           TEXT PRIMARY KEY REFERENCES versions(sha256),
    deprecated_at    TIMESTAMPTZ NOT NULL,
    sunset_at        TIMESTAMPTZ NOT NULL,          -- registry starts refusing resolves at this time
    successor_sha256 TEXT REFERENCES versions(sha256),
    reason           TEXT NOT NULL,
    announced_by     TEXT NOT NULL
);
```

Design rules worth calling out:

- **`versions` is append-only.** No `UPDATE`. A mistake becomes a new version plus a deprecation entry; the mutable alias moves. The audit trail survives.
- **`alias_history` is the audit surface.** Every alias move is a row. A reviewer asking "who moved `prod` on 2026-10-14?" gets a name and a reason in one query.
- **Lineage is a DAG, not a tree.** A dataset can have multiple parents (e.g., English + Spanish merged); a judge can depend on a prompt and a reference model.
- **`storage_uri` is opaque to the resolver.** The registry stores "where the bytes live"; the resolver signs a short-lived URL for the caller. Changing object stores is a migration, not a schema change.

### 2.3 Manifest schemas per artifact type

Each `versions.metadata_json` conforms to a type-specific manifest. The resolver validates the manifest shape at publish time; a push with an unknown field fails.

Dataset manifest:

```json
{
  "schema_version": 1,
  "artifact_type": "dataset",
  "artifact_id": "datasets/billing-chats",
  "semver": "4.2.1",
  "row_count": 12480,
  "slices": {
    "lang:en": 8120, "lang:es": 2220, "lang:de": 1180,
    "intent:billing": 3340, "intent:support": 9140
  },
  "schema_sha256": "...",
  "pii_policy": "redacted-by-redactor-v2.1",
  "sort_order": "by item_id ascending (lexical)",
  "normalization": "utf-8 nfc; strip trailing whitespace",
  "parents": [
    {"sha256": "raw-chats@sha256:ab...", "role": "source"},
    {"sha256": "redactor@sha256:cd...",  "role": "producer"}
  ],
  "license": "internal-use-only",
  "owner_team": "model-eval@team"
}
```

Judge manifest:

```json
{
  "schema_version": 1,
  "artifact_type": "judge",
  "artifact_id": "judges/helpfulness-v2",
  "semver": "1.3.0",
  "backbone": {"model_id": "llm-judge-v3", "model_sha256": "..."},
  "prompt_sha256": "prompts/judge-helpfulness@sha256:ef...",
  "decoding": {"temperature": 0.0, "max_tokens": 128, "top_p": 1.0},
  "rubric_sha256": "rubrics/helpfulness-v2@sha256:...",
  "calibration": {
    "human_agreement_k": 0.74, "n_pairs": 480, "agreement_slice": "lang:en"
  },
  "deprecates": null,
  "owner_team": "model-eval@team"
}
```

Metric manifest:

```json
{
  "schema_version": 1,
  "artifact_type": "metric",
  "artifact_id": "metrics/semantic-f1",
  "semver": "0.4.2",
  "source_sha256": "code/metrics/semantic_f1.py@sha256:...",
  "python_requires": ">=3.11",
  "direction": "higher_is_better",
  "aggregator_default": {"kind": "bootstrap_mean", "iters": 1000},
  "deterministic_seed_required": true,
  "owner_team": "model-eval@team"
}
```

Each manifest shape is validated with a JSON Schema committed in `schemas/`. A push with a missing required field is rejected at the API, not at the eval runner where the surface area is large.

### 2.4 SemVer policy

The policy is per-artifact-type and committed in `docs/registry-policy.md`. The resolver refuses pushes that conflict with it.

| Artifact | Major | Minor | Patch |
|---|---|---|---|
| dataset | Schema change; slice taxonomy change; removal of rows at scale | New optional field; added rows that do not shift slice proportions > 5% | Row-level label corrections; typo fixes; metadata-only edits |
| metric | Formula change; change of direction; change of aggregator default | New optional kwarg; new logging surface | Pure refactor; documentation; test changes |
| judge | Prompt rewrite; backbone model change; rubric change | New slice calibration; new refusal rule | Typo in system prompt; non-semantic reformat |
| prompt | Instruction change that shifts outputs on a held-out probe > 2pp | New optional slot; new example | Whitespace / comment |
| model | Weights changed; tokenizer changed | New adapter added; new stop sequence | Serialization-format repack |
| run_config | Slice gate added/removed; disposition changed; metric added/removed | Threshold change within same direction | Comments; renames |

Two rules the policy enforces:

- **Any judge backbone-model change is a MAJOR.** A new backbone shifts judgments across the whole dataset even if the prompt is identical; a minor bump lets it ride unnoticed into a `prod` alias.
- **Patch-level dataset changes still trigger a baseline rerun.** The gate uses `sha256`, not `v4.2.*`; a patch that corrects 30 labels will move slice aggregates and the downstream baseline must be republished.

### 2.5 Reference client

```python
"""Registry client. Five operations: register, resolve, get, tag, deprecate.

All calls are typed and pinned. The client never resolves an unpinned URI
on the hot path — resolution produces a manifest; `get` reads it."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


ArtifactType = Literal["dataset", "metric", "judge", "prompt", "model", "run_config"]


@dataclass(frozen=True)
class Manifest:
    sha256: str
    artifact_id: str
    artifact_type: ArtifactType
    semver: str
    storage_uri: str
    metadata: dict
    parents: list[str]


class Registry:
    def __init__(self, api_base: str, token: str) -> None:
        self._api = api_base
        self._token = token

    # ---- publish side -----------------------------------------------------

    def register(
        self,
        artifact_id: str,
        artifact_type: ArtifactType,
        semver: str,
        content_path: Path,
        metadata: dict,
        parents: list[str],
        signing_key_id: str,
    ) -> Manifest:
        """Upload bytes, compute SHA, write version + lineage rows, return manifest.

        Rejects at the API if:
          - the proposed semver conflicts with policy vs. prior versions,
          - any parent SHA is not in the registry,
          - the manifest fails JSON Schema validation for this artifact type,
          - the signer is not an authorized publisher for this artifact.
        """
        sha256 = _sha256_file(content_path)
        payload = {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "semver": semver,
            "sha256": sha256,
            "metadata": metadata,
            "parents": parents,
            "signing_key_id": signing_key_id,
        }
        return self._post("/versions", payload)

    def tag(
        self,
        artifact_id: str,
        alias: str,
        sha256: str,
        reason: str,
    ) -> None:
        """Move an alias. Audited; requires `aliases.move` permission on the
        (artifact_id, alias) pair."""
        self._post(
            "/aliases/move",
            {"artifact_id": artifact_id, "alias": alias, "sha256": sha256, "reason": reason},
        )

    def deprecate(self, sha256: str, sunset_at: str, successor_sha256: str | None, reason: str) -> None:
        self._post(
            "/deprecations",
            {"sha256": sha256, "sunset_at": sunset_at, "successor_sha256": successor_sha256, "reason": reason},
        )

    # ---- consume side -----------------------------------------------------

    def resolve(self, uri: str) -> Manifest:
        """Turn any URI form into a pinned manifest. The ONLY entry point a
        runner uses; bytes are never fetched without a manifest."""
        return self._get(f"/resolve?uri={uri}")

    def get(self, manifest: Manifest, dest: Path) -> Path:
        """Download the content addressed by manifest.sha256 to dest; verifies
        SHA on arrival. Raises on mismatch — a corrupted store is a hard stop."""
        signed_url = self._get(f"/download/{manifest.sha256}")["url"]
        _download_and_verify(signed_url, manifest.sha256, dest)
        return dest


def _sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for buf in iter(lambda: f.read(chunk), b""):
            h.update(buf)
    return h.hexdigest()
```

Design notes:

- **`resolve` and `get` are separate.** Resolve is cheap (one row read + ACL check); get is expensive (download + SHA verify). Dashboards, run manifests, and gate scripts only need `resolve`.
- **SHA is re-verified on every download.** Trusting the storage URI alone means a tampered bucket silently poisons every consumer. Verify, every time.
- **No implicit `latest`.** A call without `@...` errors; the client does not pick a version for the user. The error message tells them which alias is appropriate for their environment.

### 2.6 Resolver service

```python
"""Resolver. HTTP entry point; the only path from a URI to a manifest.

Rules:
  - URI without @version is rejected with 400.
  - Alias resolution reads `aliases` and logs an access record to
    `alias_access_log` for audit (which runner resolved `prod` when).
  - A resolved version past its `sunset_at` returns 410 Gone with the
    successor sha256 if present; 410 without successor if not.
  - ACL is checked here, not at `get`. A principal without read permission on
    the artifact gets a 403 even if they know the sha.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException


URI_RE = re.compile(
    r"^(?P<type>datasets|metrics|judges|prompts|models|run_configs)/"
    r"(?P<name>[a-z0-9][a-z0-9-]{1,63})@"
    r"(?P<pin>sha256:[0-9a-f]{64}|v\d+\.\d+\.\d+|[a-z][a-z0-9_-]{1,31})$"
)


app = FastAPI()


@app.get("/resolve")
def resolve(uri: str, principal: str):
    m = URI_RE.match(uri)
    if not m:
        raise HTTPException(400, f"invalid URI: {uri}")
    artifact_id = f"{m['type']}/{m['name']}"
    pin = m["pin"]

    if pin.startswith("sha256:"):
        sha = pin.removeprefix("sha256:")
    elif pin.startswith("v") and pin.count(".") == 2:
        sha = _db.sha_for_semver(artifact_id, pin)
    else:
        sha = _db.sha_for_alias(artifact_id, pin)
        _db.log_alias_access(artifact_id, pin, sha, principal)

    if not sha:
        raise HTTPException(404, f"unknown pin: {uri}")

    _acl.check_read(principal, artifact_id)

    dep = _db.deprecation(sha)
    if dep and datetime.now(timezone.utc) > dep.sunset_at:
        raise HTTPException(410, detail={"sunset_at": dep.sunset_at, "successor": dep.successor_sha256})

    return _db.manifest(sha)
```

- **URI validation is centralized.** One regex, one place. Downstream code never does ad-hoc string splits.
- **Alias access is logged per principal.** `who resolved prod on 2026-10-14?` has a single-table answer. A runner resolving `prod` 50M times/day produces 50M rows — in practice this is a sampled or batched write; the audit property is "an auditor can reconstruct the set of principals who read `prod` in a window."
- **Sunset is enforced at resolve time, not at the runner.** A deprecated dataset past its sunset returns 410; the runner cannot fetch bytes for it. The successor id is in the response so remediation is one edit.

### 2.7 Governance surface

```markdown
# docs/review-gates.md (excerpt)

## Alias move permissions
- `datasets/*@prod`   — model-eval-approvers (two-person review required)
- `datasets/*@staging`— any member of owner_team
- `judges/*@prod`     — model-eval-approvers (two-person review required)
- `metrics/*@prod`    — model-eval-approvers + platform-eng (two-person)
- `*/latest`          — any member of owner_team (dev use only)

## Deprecation lifecycle
1. Owner opens a deprecation PR naming the version, successor, and reason.
2. Registry marks `deprecated_at = now`, `sunset_at = now + 90 days`.
3. Consumers' run manifests that still pin the deprecated sha fire a WARN at
   resolve; the warning is surfaced in the Grafana dashboard and the per-run
   REPORT.md.
4. At `sunset_at`, resolver returns 410. Any live pipeline still pinning the
   sha fails fast with a successor hint.

## Review gates at publish
- A dataset publish to `prod` requires: schema-check passed, PII scan passed,
  slice-floor validation passed (see mod-110 exercise-01), two approvers.
- A judge publish to `prod` requires: human-agreement calibration ≥ 0.70
  kappa on the last 400 pairs, two approvers.
- A metric publish to `prod` requires: unit tests passing, determinism test
  passing (two reruns byte-identical), one approver.
```

The governance doc is itself a registry artifact (`run_configs/registry-policy@v1.2`): changes are versioned and reviewed like any other config.

## 3. Validation steps

1. **URI grammar.** Parser tests cover: valid sha256 form, valid semver, valid alias, missing `@`, unknown type, uppercase, invalid characters. A URI without `@` is rejected with a 400; the error names the artifact type and alias conventions.
2. **Immutability.** Attempting to `UPDATE` a row in `versions` fails via a database `BEFORE UPDATE` trigger that raises. A publish that reuses an existing sha with different metadata is rejected at the API with "sha already registered; use a new version".
3. **SemVer policy enforcement.** A publish with semver `1.2.0` after `1.1.0` is accepted; `1.0.0` after `1.1.0` is rejected (monotonic within the same major); a judge publish that changes `backbone.model_id` while only bumping minor is rejected with policy reference.
4. **Alias audit completeness.** Every call to `tag` produces exactly one row in `aliases` (upsert) and one row in `alias_history` (append). A SQL check `SELECT count(*) FROM alias_history WHERE moved_by IS NULL` returns zero.
5. **Lineage completeness.** Every `dataset` and `judge` publish has ≥ 1 parent edge in `lineage_edges`; publishes without a parent are allowed only for the type `raw_source` with an explicit `--root` flag plus a two-person approval.
6. **Deprecation enforcement.** A resolve of a sunset-passed sha returns 410 with the successor id. A resolve before sunset returns 200 with a `warnings: [deprecated_until]` field surfaced in the manifest.
7. **ACL on resolve.** A principal not in the artifact's ACL gets a 403 on both aliases and shas. A log entry records the deny.
8. **Content integrity.** `get` fails if the downloaded content's sha does not match the manifest sha; the failure is a hard 500, not a warning.
9. **Determinism on alias resolution.** For a fixed (artifact, alias), two concurrent resolves return the same sha even under alias moves (read consistency guaranteed by the resolver's transaction).
10. **Publish round-trip.** Register → resolve by semver → resolve by alias → get: the manifest's `sha256` is identical across the three resolve paths; the downloaded content's sha matches.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the registry being **an auditable control plane**, not a key-value store.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Content-addressed storage with mandatory SHA on every version | 1 | `versions.sha256` is PK; publish rejects duplicate SHAs with different metadata. |
| R2 | Immutable versions; mutable aliases in a separate table | 1 | `UPDATE` on `versions` raises; `aliases` is upsert-only; test covers both. |
| R3 | URI grammar enforces type + name + pin on every reference | 1 | Resolver rejects bare names; parser has positive/negative tests for every pin form. |
| R4 | SemVer policy per artifact type, enforced at publish | 2 | `docs/registry-policy.md` names major/minor/patch triggers per type; API tests cover a rejected downgrade and a rejected minor-with-breaking-change. |
| R5 | Lineage DAG; every derived artifact names its parents | 1 | `lineage_edges` has ≥ 1 row per derived publish; roots require explicit flag + approval. |
| R6 | Alias moves and alias resolution are audited per principal | 1 | `alias_history` append-only; `alias_access_log` populated; auditor can list who resolved `prod` in a window. |
| R7 | Deprecation lifecycle with announced sunset; resolver returns 410 past sunset | 1 | `deprecations` schema with `sunset_at`; integration test covers the 410 path. |
| R8 | ACLs on publish and on resolve; two-person approval for `prod` aliases | 1 | `docs/review-gates.md` names approver groups; API tests cover deny and dual-approval. |
| R9 | Reference client exposes exactly `register`, `resolve`, `get`, `tag`, `deprecate` — nothing implicit | 1 | Public API surface is five methods; no bare-name resolution; SHA verified on every `get`. |

**Passing bar:** 7 / 10. R1 and R2 are non-negotiable — a registry that permits a silent byte change is not a registry. R4 is the most commonly weak point; a policy that is not enforced by the API will decay in weeks.

Reviewer checklist:

- [ ] Every artifact URI in run manifests pins a version (sha, semver, or audited alias).
- [ ] `versions` table has an immutability trigger; `aliases` move history is append-only.
- [ ] Every derived artifact has ≥ 1 lineage edge.
- [ ] `prod` alias moves require two approvers and leave a `reason` in the audit log.
- [ ] Judge backbone-model changes are MAJORs; the policy is enforced by the API.
- [ ] Deprecated artifacts past `sunset_at` return 410 with a successor hint.
- [ ] A `get` against a corrupted blob fails with a SHA-mismatch error, not a warning.
- [ ] Resolver logs `alias_access` for every alias resolution (sampled or complete, per policy).

## 5. Common mistakes

- **One big `artifacts` table with a JSON `data` column and a `type` field.** Querying lineage, enforcing per-type schema, and auditing aliases all degrade to full-table scans. Separate versions, aliases, lineage.
- **Mutable versions.** "Fix the typo in v4" rewrites history. Every downstream run manifest that pinned the sha now references a different byte stream. Publish v4.0.1 and move the alias.
- **Aliases stored in a comment / README.** `docs/aliases.md: prod = v4` is not enforceable — the resolver cannot read it. Put aliases in a table the resolver reads at every resolve.
- **Bare-name resolution in the client.** A client that defaults to `@latest` when `@...` is missing lets a dev-time habit become a prod run manifest. Reject bare names at the API.
- **Judge backbone change as a minor.** "We only changed the model, prompt is the same" shifts every verdict. MAJOR, and the change triggers a judge-recalibration run before `prod` can move.
- **Dataset patch without baseline rerun.** A 0.0.1 bump that corrects 30 labels shifts slice aggregates by tenths of a point; the downstream gate on "delta vs. baseline" now spuriously fails. Patch publishes should trigger a baseline-rerun ticket.
- **No lineage root policy.** A dataset with no parents is either genuinely raw or the operator forgot. Require an explicit root flag plus approval; make the common case (derived) default-safe.
- **Alias move with no `reason`.** A `prod` alias moved at 02:14 with reason "update" is a time bomb; six months later nobody knows why. Require a non-trivial reason string; lint for a minimum length.
- **Deprecation without sunset.** "Deprecated" with no end date is a wish, not a lifecycle. The sunset date is what the resolver enforces; without it the deprecated artifact rides forever.
- **Signed URL as the identity.** The signed URL is an ephemeral download token; the SHA is the identity. A client that stores the URL and re-uses it after rotation breaks.
- **ACLs on download only, not on resolve.** If anyone can resolve `datasets/*@prod` and read the metadata, that is an information leak (slice sizes, schema, parents). ACLs belong at the resolver.
- **One global `latest` alias used in prod runs.** `latest` is a dev convenience. A gate run that pins `datasets/billing-chats@latest` reruns against different bytes every month. Pin `@v4.2.1` or `@prod` (which is audited).

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `GOVERN` function asks for documented, enforced provenance policies across the AI lifecycle; a content-addressed registry with mandatory lineage edges and audited alias moves is the direct operationalization. `MAP` asks that artifacts, roles, and relationships be enumerated; the lineage DAG plus per-artifact owner metadata is the enumeration.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML06 AI Supply Chain Attacks** is the registry's primary threat model — an unsigned dataset mutated in place silently rewires every downstream eval; mandatory SHA and immutable versions are the control. **ML02 Data Poisoning Attack** is why aliases must be auditable: a `prod` alias moved out-of-band lets a poisoned version ride into every gated run. **ML05 Model Theft** motivates ACLs at resolve, not just at download: metadata (slice sizes, schema) is itself sensitive.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0010 ML Supply Chain Compromise` and `AML.T0020 Poison Training Data` describe the registry as a defended control plane; the signed, content-addressed version plus two-person approval on `prod` alias moves is the control. `AML.T0019 Publish Poisoned Datasets` motivates the deprecation lifecycle with announced sunset — the registry must be able to say "stop using this version" with teeth.

<!-- Local exercise context: The specific artifact names (`billing-chats`, `helpfulness-v2`, `semantic-f1`), the 90-day sunset window, the 0.70 kappa human-agreement threshold for judge `prod` promotion, and the two-person approval for `prod` alias moves are illustrative defaults for a chat-product eval platform. Replace them with your platform's artifact taxonomy, approval groups, and calibration targets before adopting. Sibling exercises: the orchestration layer that consumes these resolved manifests is [exercise-02](../exercise-02-multi-runner-orchestration/SOLUTION.md); the cost-control plane that budgets registry reads and runner cost against resolved manifests is [exercise-03](../exercise-03-platform-cost-controls/SOLUTION.md); the warehouse that reads lineage edges as its join plan is [exercise-04](../exercise-04-eval-data-warehouse-and-lineage/SOLUTION.md); the CI pipeline that resolves every URI in a run manifest before gating is [exercise-05](../exercise-05-eval-in-ci-with-slo/SOLUTION.md). -->
