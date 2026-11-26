# exercise-04 — Eval Data Warehouse and Lineage — Solution

## 1. Solution overview

An eval platform that stores per-run JSON blobs in object storage and nothing else is a platform where the question "has this slice regressed on this model family over the last six months?" takes a day to answer with a notebook. A warehouse turns per-run evidence into a **queryable, joinable, lineage-traversable** substrate: a reviewer can ask "which runs on `billing-chats@v4` produced a drop on `intent:billing` and which judge decided they passed," get one SQL query's answer, and follow every edge back to the artifact that caused the delta. The design target is an eval warehouse that is reproducible (every fact row carries the SHAs that produced it), slice-first (slices are dimensions, not JSON fields), and lineage-aware (every artifact row names its parents and producers).

The design hinges on four non-negotiables:

- **Star schema with slice dimensions.** One `fact_eval_scores` table at the grain of `(run_id, shard_id, item_id, metric)`; one `fact_run_aggregates` at the grain of `(run_id, slice_id, metric)`. Slices are a dimension (`dim_slice`); metrics are a dimension (`dim_metric`). Querying "worst-regressed slice across the last 30 runs" is a GROUP BY, not a glob over JSON.
- **Every fact row pins the artifact SHAs.** `dataset_sha`, `model_sha`, `judge_sha`, `metric_sha`, `pricing_sha`, `runner_commit`. A six-month-old row can be reproduced because every input is named.
- **Lineage is a graph table, not a tangle of foreign keys.** `fact_lineage_edges` names `(child_sha, parent_sha, producer_sha, role)` and is walked for both artifact provenance (which upstream datasets built this one?) and run provenance (which runs read this dataset?). The graph is the single traversal surface.
- **Writes are idempotent; schema evolves with versioned migrations.** A replayed completion hook does not double-insert; a new metric kind is a new row in `dim_metric` plus a migration that backfills nulls. "Just add a column" to a live warehouse is a six-hour outage.

The reference answer has five deliverables:

1. A **schema** (`warehouse.sql`) — fact and dimension tables with keys, slices, metrics, lineage, and cost rows.
2. An **ingestion pipeline** (`ingest.py`) — reads completed shard artifacts from the orchestrator, normalizes slice tags, writes facts idempotently.
3. A **lineage model** (`lineage.sql` + `lineage.py`) — queries for "what produced X", "what consumed X", "what are the common ancestors of these two runs."
4. **Analysis queries** (`queries/*.sql`) — the committed set a reviewer actually runs: slice regression deltas, judge-agreement over time, cost per 1k items by model.
5. A **governance policy** (`docs/warehouse-policy.md`) — retention, PII, access, backfill, and migration procedure.

This maps directly to the NIST AI RMF `MEASURE` function, which asks that "evaluations be retained, queryable, and traceable to the inputs that produced them" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The lineage graph is the direct operationalization of `GOVERN`'s requirement that "provenance across the lifecycle be documented and verifiable." The adversarial lens is OWASP ML Top 10 **ML06 AI Supply Chain Attacks** (the warehouse is the ground-truth reconstructor: if `fact_eval_scores` pins `dataset_sha` and `judge_sha`, a silent swap in the registry cannot retroactively mislabel historical passes) and **ML02 Data Poisoning Attack** (slice-level fact rows let a reviewer detect a poisoning signature — a specific slice that suddenly improved past plausibility — that aggregate rows would hide) ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `AML.T0010 ML Supply Chain Compromise` frames the warehouse as the forensic surface: if a backdoor is suspected, the warehouse is where the pre-compromise baseline is read; if the lineage graph is intact, the attribution is a query away ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked design and implementation

### 2.1 Star schema

```sql
-- Dimensions --------------------------------------------------------------

CREATE TABLE dim_run (
    run_id              TEXT PRIMARY KEY,
    purpose             TEXT NOT NULL,             -- nightly-regression | pr-gate | ad-hoc
    environment         TEXT NOT NULL,
    team                TEXT NOT NULL,
    requested_by        TEXT NOT NULL,
    requested_at        TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    spec_sha            TEXT NOT NULL,             -- the RunSpec sha
    status              TEXT NOT NULL              -- completed | failed | cancelled
);

CREATE TABLE dim_artifact (
    sha256              TEXT PRIMARY KEY,
    artifact_type       TEXT NOT NULL,             -- dataset|metric|judge|prompt|model|run_config
    artifact_id         TEXT NOT NULL,             -- "datasets/billing-chats"
    semver              TEXT NOT NULL,             -- "4.2.1"
    owner_team          TEXT NOT NULL,
    metadata_json       JSONB NOT NULL
);

CREATE TABLE dim_slice (
    slice_id            BIGSERIAL PRIMARY KEY,
    slice_key           TEXT NOT NULL UNIQUE,      -- "lang:en&intent:billing" (canonicalized)
    dataset_sha         TEXT NOT NULL REFERENCES dim_artifact(sha256),
    tags                JSONB NOT NULL,            -- {"lang": "en", "intent": "billing"}
    size_in_dataset     INTEGER NOT NULL,
    size_floor          INTEGER NOT NULL
);

CREATE TABLE dim_metric (
    metric_id           BIGSERIAL PRIMARY KEY,
    metric_sha          TEXT NOT NULL UNIQUE REFERENCES dim_artifact(sha256),
    name                TEXT NOT NULL,
    direction           TEXT NOT NULL,             -- higher_is_better | lower_is_better
    aggregator          TEXT NOT NULL              -- bootstrap_mean | wilson | quantile
);

CREATE TABLE dim_judge (
    judge_sha           TEXT PRIMARY KEY REFERENCES dim_artifact(sha256),
    name                TEXT NOT NULL,
    backbone_model_sha  TEXT NOT NULL,
    prompt_sha          TEXT NOT NULL,
    calibration_kappa   NUMERIC,
    calibration_n_pairs INTEGER
);

CREATE TABLE dim_time (                             -- date dimension; standard calendar
    date_id             DATE PRIMARY KEY,
    year                INTEGER NOT NULL,
    month               INTEGER NOT NULL,
    week_iso            INTEGER NOT NULL,
    day_of_week         INTEGER NOT NULL,
    is_business_day     BOOLEAN NOT NULL
);

-- Facts -------------------------------------------------------------------

CREATE TABLE fact_eval_scores (
    run_id              TEXT NOT NULL REFERENCES dim_run(run_id),
    shard_id            TEXT NOT NULL,
    item_id             TEXT NOT NULL,
    metric_id           BIGINT NOT NULL REFERENCES dim_metric(metric_id),
    slice_id            BIGINT NOT NULL REFERENCES dim_slice(slice_id),
    score               NUMERIC NOT NULL,          -- per-item metric value
    verdict             TEXT,                       -- judge verdict (good|bad|tie|invalid) if applicable
    model_sha           TEXT NOT NULL REFERENCES dim_artifact(sha256),
    dataset_sha         TEXT NOT NULL REFERENCES dim_artifact(sha256),
    judge_sha           TEXT REFERENCES dim_artifact(sha256),
    predictions_sha     TEXT NOT NULL,              -- the shard's predictions blob sha
    recorded_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (run_id, shard_id, item_id, metric_id)
);

CREATE TABLE fact_run_aggregates (
    run_id              TEXT NOT NULL REFERENCES dim_run(run_id),
    slice_id            BIGINT NOT NULL REFERENCES dim_slice(slice_id),
    metric_id           BIGINT NOT NULL REFERENCES dim_metric(metric_id),
    n_items             INTEGER NOT NULL,
    point               NUMERIC NOT NULL,
    ci_low              NUMERIC,
    ci_high             NUMERIC,
    baseline_run_id     TEXT REFERENCES dim_run(run_id),
    delta_vs_baseline   NUMERIC,
    gate_verdict        TEXT,                       -- pass | fail | low_power | n/a
    recorded_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (run_id, slice_id, metric_id)
);

CREATE TABLE fact_cost (                             -- from the cost controller (exercise-03)
    run_id              TEXT NOT NULL REFERENCES dim_run(run_id),
    shard_id            TEXT NOT NULL,
    backend             TEXT NOT NULL,
    dollars             NUMERIC NOT NULL,
    units               NUMERIC NOT NULL,
    unit_kind           TEXT NOT NULL,              -- tokens | seconds | items
    pricing_sha         TEXT NOT NULL REFERENCES dim_artifact(sha256),
    recorded_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (run_id, shard_id, backend)
);

-- Lineage graph -----------------------------------------------------------

CREATE TABLE fact_lineage_edges (
    child_sha           TEXT NOT NULL REFERENCES dim_artifact(sha256),
    parent_sha          TEXT NOT NULL REFERENCES dim_artifact(sha256),
    producer_sha        TEXT NOT NULL REFERENCES dim_artifact(sha256),
    role                TEXT NOT NULL,              -- source | redactor | augmenter | derived_from
    recorded_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (child_sha, parent_sha, producer_sha, role)
);

CREATE TABLE fact_run_consumed_artifacts (            -- "this run read these artifacts"
    run_id              TEXT NOT NULL REFERENCES dim_run(run_id),
    artifact_sha        TEXT NOT NULL REFERENCES dim_artifact(sha256),
    role                TEXT NOT NULL,              -- dataset | model | judge | metric | prompt | pricing
    PRIMARY KEY (run_id, artifact_sha, role)
);
```

Rules the schema enforces:

- **`dim_slice.slice_key` is canonicalized.** `lang:en&intent:billing` and `intent:billing&lang:en` must produce the same slice row. A parser normalizes to sorted-by-key form; the unique constraint is the enforcement.
- **`fact_eval_scores` is at per-item grain.** Aggregating at write-time loses the ability to re-slice. Storage is cheap compared to re-running the eval.
- **Every fact row has the SHAs.** A six-month-old score row names the dataset, model, judge, and metric SHAs that produced it; a registry restore could reconstruct the exact inputs.
- **`fact_lineage_edges` is a general graph table.** One traversal for artifact-to-artifact lineage, one traversal for run-to-artifact ("which runs read this dataset"), one traversal for transitive ancestor queries.

### 2.2 Ingestion pipeline

```python
"""Ingest. Called once per shard completion and once per run completion.

Reads:
  - the orchestrator's shard metadata (manifest, status),
  - the shard's predictions blob (per-item scores, verdicts),
  - the run's REPORT.json (per-slice aggregates, baseline deltas).

Writes:
  - fact_eval_scores: one row per (run_id, shard_id, item_id, metric).
  - fact_run_aggregates: one row per (run_id, slice_id, metric_id).
  - fact_cost: one row per (run_id, shard_id, backend).
  - fact_run_consumed_artifacts: one row per (run_id, artifact_sha, role).

All writes are idempotent on their PK; a replayed hook does not duplicate."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ShardCompletion:
    run_id: str
    shard_id: str
    predictions_uri: str
    predictions_sha: str
    item_range: tuple[int, int]
    model_sha: str
    dataset_sha: str
    judge_sha: str | None
    completed_at: str


class Ingester:
    def __init__(self, db, blob_store, registry) -> None:
        self._db = db
        self._blob = blob_store
        self._reg = registry

    def on_shard_completed(self, completion: ShardCompletion) -> None:
        self._ensure_dimensions(completion)
        preds = self._blob.read(completion.predictions_uri)
        self._verify_sha(preds, completion.predictions_sha)

        rows = []
        for pred in preds["items"]:
            for score in pred["scores"]:
                slice_id = self._slice_id(completion.dataset_sha, pred["slice_tags"])
                metric_id = self._metric_id(score["metric_sha"])
                rows.append({
                    "run_id": completion.run_id,
                    "shard_id": completion.shard_id,
                    "item_id": pred["item_id"],
                    "metric_id": metric_id,
                    "slice_id": slice_id,
                    "score": score["value"],
                    "verdict": pred.get("verdict"),
                    "model_sha": completion.model_sha,
                    "dataset_sha": completion.dataset_sha,
                    "judge_sha": completion.judge_sha,
                    "predictions_sha": completion.predictions_sha,
                    "recorded_at": completion.completed_at,
                })
        # upsert on PK (run_id, shard_id, item_id, metric_id)
        self._db.upsert("fact_eval_scores", rows,
                        pk=("run_id", "shard_id", "item_id", "metric_id"))

    def on_run_completed(self, run_id: str, report: dict) -> None:
        agg_rows = []
        for slice_entry in report["per_slice"]:
            slice_id = self._slice_id(report["dataset_sha"], slice_entry["slice_tags"])
            for m in slice_entry["metrics"]:
                metric_id = self._metric_id(m["metric_sha"])
                agg_rows.append({
                    "run_id": run_id,
                    "slice_id": slice_id,
                    "metric_id": metric_id,
                    "n_items": m["n"],
                    "point": m["point"],
                    "ci_low": m.get("ci_lo"),
                    "ci_high": m.get("ci_hi"),
                    "baseline_run_id": report.get("baseline_run_id"),
                    "delta_vs_baseline": m.get("delta"),
                    "gate_verdict": m.get("gate_verdict"),
                    "recorded_at": report["completed_at"],
                })
        self._db.upsert("fact_run_aggregates", agg_rows,
                        pk=("run_id", "slice_id", "metric_id"))

        # Record every artifact the run read, so downstream queries can
        # answer "which runs used this judge."
        consumed = []
        for sha in report["consumed_artifacts"]:
            consumed.append({"run_id": run_id, "artifact_sha": sha["sha"], "role": sha["role"]})
        self._db.upsert("fact_run_consumed_artifacts", consumed,
                        pk=("run_id", "artifact_sha", "role"))

    def _slice_id(self, dataset_sha: str, tags: dict[str, str]) -> int:
        key = "&".join(f"{k}:{v}" for k, v in sorted(tags.items()))
        return self._db.get_or_insert_slice(dataset_sha=dataset_sha, slice_key=key, tags=tags)

    def _metric_id(self, metric_sha: str) -> int:
        return self._db.get_or_insert_metric(metric_sha=metric_sha)

    def _ensure_dimensions(self, completion: ShardCompletion) -> None:
        for sha in filter(None, [completion.model_sha, completion.dataset_sha, completion.judge_sha]):
            if not self._db.artifact_exists(sha):
                manifest = self._reg.manifest(sha)
                self._db.upsert_artifact(manifest)
                for parent, producer, role in self._reg.lineage(sha):
                    self._db.upsert_lineage_edge(sha, parent, producer, role)
```

Rules the ingester enforces:

- **Upsert on PK, never insert-only.** A webhook replayed after a crash does not duplicate. A test replays the same completion three times and asserts row counts are unchanged.
- **Lineage is backfilled from the registry on dimension-ensure.** The warehouse never has a fact row whose SHAs are not resolvable to a dimension; a missing lineage edge is a bug that blocks ingest, not a warning.
- **Predictions blob is SHA-verified at read.** A tampered blob does not get ingested; the shard row is marked `ingest_failed` with the mismatch recorded.

### 2.3 Lineage queries

```sql
-- "What produced dataset X?" — walk ancestors
WITH RECURSIVE ancestors AS (
    SELECT child_sha, parent_sha, producer_sha, role, 1 AS depth
    FROM fact_lineage_edges
    WHERE child_sha = :target_sha
    UNION ALL
    SELECT e.child_sha, e.parent_sha, e.producer_sha, e.role, a.depth + 1
    FROM fact_lineage_edges e
    JOIN ancestors a ON e.child_sha = a.parent_sha
    WHERE a.depth < 20
)
SELECT parent_sha, producer_sha, role, MIN(depth) AS depth
FROM ancestors
GROUP BY parent_sha, producer_sha, role
ORDER BY depth;

-- "Which runs consumed this judge, and how did they score?"
SELECT
    r.run_id, r.requested_at, r.team,
    a.point, a.delta_vs_baseline, a.gate_verdict,
    s.slice_key, m.name AS metric
FROM fact_run_consumed_artifacts c
JOIN dim_run r ON r.run_id = c.run_id
JOIN fact_run_aggregates a ON a.run_id = r.run_id
JOIN dim_slice s ON s.slice_id = a.slice_id
JOIN dim_metric m ON m.metric_id = a.metric_id
WHERE c.artifact_sha = :judge_sha AND c.role = 'judge'
ORDER BY r.requested_at DESC;

-- "Common ancestors of two runs' datasets"
WITH RECURSIVE
  a AS (
    SELECT c.artifact_sha FROM fact_run_consumed_artifacts c
    WHERE c.run_id = :run_a AND c.role = 'dataset'
    UNION ALL
    SELECT e.parent_sha FROM fact_lineage_edges e JOIN a ON a.artifact_sha = e.child_sha
  ),
  b AS (
    SELECT c.artifact_sha FROM fact_run_consumed_artifacts c
    WHERE c.run_id = :run_b AND c.role = 'dataset'
    UNION ALL
    SELECT e.parent_sha FROM fact_lineage_edges e JOIN b ON b.artifact_sha = e.child_sha
  )
SELECT artifact_sha FROM a INTERSECT SELECT artifact_sha FROM b;
```

Rules the queries enforce:

- **Recursive CTEs are depth-bounded.** `depth < 20` is a hard stop; a cyclic lineage graph is a bug but should not hang the query.
- **Shared SHAs make joins trivial.** The warehouse does not need a separate "tag" or "name" for lineage lookups; everything joins on `sha256`.

### 2.4 Analysis queries

```sql
-- queries/slice_regression_deltas.sql
-- Top worst slice regressions across the last N runs of a given purpose.
SELECT
    r.run_id, r.requested_at,
    s.slice_key, m.name AS metric,
    a.point AS cand_point,
    b.point AS base_point,
    a.delta_vs_baseline AS delta,
    a.gate_verdict
FROM fact_run_aggregates a
JOIN dim_run r ON r.run_id = a.run_id
JOIN fact_run_aggregates b
  ON b.run_id = a.baseline_run_id AND b.slice_id = a.slice_id AND b.metric_id = a.metric_id
JOIN dim_slice s ON s.slice_id = a.slice_id
JOIN dim_metric m ON m.metric_id = a.metric_id
WHERE r.purpose = :purpose
  AND r.requested_at >= :since
  AND m.direction = 'higher_is_better'
ORDER BY a.delta_vs_baseline ASC
LIMIT 50;

-- queries/judge_agreement_over_time.sql
-- For a judge, how did its average verdict distribution shift week-over-week?
SELECT
    date_trunc('week', recorded_at) AS week,
    verdict,
    COUNT(*)::float / SUM(COUNT(*)) OVER (PARTITION BY date_trunc('week', recorded_at)) AS share
FROM fact_eval_scores
WHERE judge_sha = :judge_sha
  AND recorded_at >= now() - interval '90 days'
GROUP BY 1, verdict
ORDER BY 1, verdict;

-- queries/cost_per_1k_items_by_model.sql
SELECT
    c.pricing_sha, m.name AS model_name,
    SUM(c.dollars) / (SUM(c.units) / 1000.0) FILTER (WHERE c.unit_kind = 'items') AS dollars_per_1k
FROM fact_cost c
JOIN fact_run_consumed_artifacts rca ON rca.run_id = c.run_id AND rca.role = 'model'
JOIN dim_artifact m ON m.sha256 = rca.artifact_sha
GROUP BY c.pricing_sha, m.name
HAVING SUM(c.units) FILTER (WHERE c.unit_kind = 'items') > 0
ORDER BY dollars_per_1k DESC;

-- queries/slo_burn_by_slice_month.sql
-- How many gate-fail events per slice per month in `prod`?
SELECT
    date_trunc('month', r.requested_at) AS month,
    s.slice_key,
    COUNT(*) FILTER (WHERE a.gate_verdict = 'fail') AS n_fails,
    COUNT(*) AS n_runs
FROM fact_run_aggregates a
JOIN dim_run r ON r.run_id = a.run_id
JOIN dim_slice s ON s.slice_id = a.slice_id
WHERE r.environment = 'prod' AND a.gate_verdict IS NOT NULL
GROUP BY 1, 2
ORDER BY 1 DESC, n_fails DESC;
```

These queries are the committed set: a reviewer who asks a new question first checks `queries/` for an existing answer. Query drift — ten engineers writing ten versions of the same regression query — is prevented by keeping the committed queries small, well-named, and parameterized.

### 2.5 Governance

```markdown
# docs/warehouse-policy.md (excerpt)

## Retention
- `fact_eval_scores`: 365 days online; archived to cold storage for 7 years.
- `fact_run_aggregates`: indefinite (small; audit horizon).
- `fact_cost`: 7 years (finance requirement).
- `fact_lineage_edges`: indefinite (lineage is reconstruction evidence).

## PII and sensitive content
- Per-item score rows do NOT include raw prompts or outputs. The `item_id` is
  a hash; the raw text lives in the privacy-redacted blob store with its own
  ACL (see exercise-05 of mod-110 on observability). A warehouse reader can
  tell *which* items regressed; they cannot read the text without a second
  authorization step.
- Judge verdicts ARE in the warehouse (categorical, not text).

## Access
- Read: any eval engineer in the org can query dims and aggregates.
  Per-item fact rows require membership in the owning team OR a time-limited
  "incident-investigator" role.
- Write: ingest service only. Direct `INSERT` is revoked at the role level.

## Backfill and migrations
- New metric kind: add a `dim_metric` row, write a backfill query that marks
  prior aggregates as `metric_coverage='partial'` for the affected rows; a
  WARN is surfaced on queries that mix partial and complete coverage.
- Schema change: a migration PR includes the DDL, the backfill, the
  shadow-read validation (compare old and new schema on a 24h sample before
  cutover), and the rollback script.

## Data quality
- Daily job: `assert COUNT(fact_eval_scores where predictions_sha NOT IN SELECT sha FROM blob_registry) = 0`.
  A dangling predictions SHA means the blob store diverged from the warehouse; incident-level.
- Weekly: ingest completeness check — every `dim_run.status = 'completed'`
  has aggregates in `fact_run_aggregates`. Gaps are backfilled by a replay
  of the on_run_completed hook.
```

## 3. Validation steps

1. **Schema round-trip.** `warehouse.sql` applies cleanly to a fresh database; a second apply is a no-op; drop and reapply reproduces the same object DDL.
2. **Idempotent ingest.** Replaying `on_shard_completed` three times for the same completion results in one `fact_eval_scores` row per (run_id, shard_id, item_id, metric_id); a diff of the table is empty after replay.
3. **Slice canonicalization.** `{"intent":"billing","lang":"en"}` and `{"lang":"en","intent":"billing"}` produce the same `dim_slice.slice_id`.
4. **Predictions SHA verification.** An ingest of a predictions blob whose sha does not match the manifest's `predictions_sha` fails the shard; a quarantine row is written; no `fact_eval_scores` rows are created.
5. **Lineage completeness on ingest.** For every new `dim_artifact` row, at least one `fact_lineage_edges` row is written (unless the artifact is tagged `is_root` and approved).
6. **Query determinism.** `queries/slice_regression_deltas.sql` run twice against a frozen snapshot produces byte-identical output.
7. **Depth bound on recursion.** A synthetic lineage cycle does not hang the ancestors query; depth bound terminates.
8. **PII absence in facts.** Grep of `fact_eval_scores`-producing code paths for raw-prompt fields returns nothing; a schema CI check verifies no column with a text-blob role.
9. **Cost reconciliation.** `SELECT SUM(dollars) FROM fact_cost WHERE run_id = :r` equals the `cost_rows`-side total from the cost controller (see [exercise-03](../exercise-03-platform-cost-controls/SOLUTION.md)); divergence > $0.01 fails CI.
10. **Completeness check.** Every `dim_run.status = 'completed'` has at least one row in `fact_run_aggregates`; a gap raises an ingest-missing alert.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the warehouse being **a lineage-aware star schema with per-item facts**, not a JSON archive.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Star schema with explicit dim and fact tables; slices are a dimension | 2 | `dim_slice`, `dim_metric`, `dim_judge` etc. present; `fact_eval_scores` references them. |
| R2 | Every fact row pins the artifact SHAs that produced it | 1 | `dataset_sha`, `model_sha`, `judge_sha`, `predictions_sha` are not nullable on fact. |
| R3 | Lineage graph table supports artifact and run provenance in one traversal | 1 | `fact_lineage_edges` + `fact_run_consumed_artifacts`; a recursive CTE walks both. |
| R4 | Ingest is idempotent on (run_id, shard_id, item_id, metric_id) and friends | 2 | Upsert pattern; replay test passes. |
| R5 | Slice keys are canonicalized before insert | 1 | Sort-by-key normalization; unique constraint enforces. |
| R6 | Predictions blob is SHA-verified on read; failure quarantines the shard | 1 | Ingest test covers the mismatch path. |
| R7 | Per-item facts do not contain raw prompt/output; hashes only | 1 | Schema linter rejects text-blob columns in fact tables. |
| R8 | Committed analysis queries parameterized and version-controlled | 1 | `queries/` directory; three required queries (slice regression, judge agreement, cost per 1k items) present. |

**Passing bar:** 7 / 10. R1 and R4 are non-negotiable — a flat JSON archive cannot answer the questions this warehouse is built to answer, and a non-idempotent ingest doubles history.

Reviewer checklist:

- [ ] Fact tables are at per-item grain; aggregates are their own table.
- [ ] Every fact row has non-null dataset/model/metric SHAs; judge SHA where applicable.
- [ ] Slices are canonicalized before insert; the unique constraint rejects duplicates.
- [ ] Ingest upserts; a triple-replayed completion hook does not create duplicates.
- [ ] A predictions blob with a wrong SHA quarantines instead of silently ingesting.
- [ ] Lineage edges are backfilled from the registry when a new artifact dimension is created.
- [ ] Per-item fact tables contain no raw text — only hashes and categorical verdicts.
- [ ] Committed queries for slice regression, judge agreement, and cost per 1k items exist and run deterministically.

## 5. Common mistakes

- **One wide table with a JSON `metrics` column.** Every slice-regression question becomes a `jsonb` path query; the planner picks sequential scans; the warehouse is too slow to use. Star schema or it is a notebook substrate.
- **Aggregating at write time.** Writing only `fact_run_aggregates` and dropping per-item rows saves disk and loses the ability to re-slice. Keep both; the cheap bytes buy years of re-analysis.
- **Slice as a free-text tag.** `"lang:en, intent:billing"` is not canonical; `"intent:billing,lang:en"` is a different row. Parse, sort, canonicalize at insert.
- **No SHA on fact rows.** The row says "exact match = 0.83 on 2026-10-12" with no reference to which dataset version, which model, which judge. The number is unreproducible six weeks later. Pin every SHA.
- **Lineage tables that are not transitive.** A single-hop `parent` column cannot answer "what are the ancestors of this dataset." Use an edge table and a recursive CTE.
- **Insert-only ingest.** A shard that fires its webhook twice produces two rows; aggregates double. Upsert on PK.
- **Raw prompts in the warehouse.** A fact table with a `prompt_text` column is a PII incident waiting to happen. Hash the text; store the raw elsewhere with its own ACL.
- **Query library of twenty variants of the same regression question.** Ten engineers will write ten versions and disagree. Commit the canonical queries; discourage copy-paste.
- **Schema migrations without shadow validation.** "Add a column" on a live warehouse is minutes of blocking DDL and hours of backfill. Shadow-write; compare; cutover.
- **No completeness check.** A run whose on_run_completed hook was lost sits forever as a `dim_run` without aggregates; the weekly report is quietly wrong. Daily gap check.
- **Cost rows separate and un-joined.** A cost analysis that cannot be joined to runs' slice outcomes cannot answer "which slice is expensive to improve." Include `run_id` and `pricing_sha` on `fact_cost`.
- **Access policy only at the role level, not row level.** A query over `fact_eval_scores` across teams shows everyone's regressions. Row-level security on `team` for per-item rows; aggregates are org-wide.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function asks that evaluations be "retained, queryable, and traceable to the inputs that produced them"; the SHA-pinned per-item fact rows and the lineage graph are the direct operationalization. The `GOVERN` function asks for documented, enforced provenance; `fact_lineage_edges` is the graph that answers "where did this come from" and `fact_run_consumed_artifacts` is the graph that answers "where did this go."
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML06 AI Supply Chain Attacks** motivates the SHA-pinning throughout: if the registry restores a correct version, the warehouse can be reconstructed byte-for-byte and the question "did a compromised dataset ride into this gate?" is a single query. **ML02 Data Poisoning Attack** motivates slice-level per-item facts: a poison signature (a specific slice that suddenly improved past plausibility) is visible in `fact_eval_scores` but hidden in `fact_run_aggregates`.
- MITRE ATLAS — <https://atlas.mitre.org/>. `AML.T0010 ML Supply Chain Compromise` frames the warehouse as the forensic surface — the pre-compromise baseline is read from here, and the lineage graph is walked here when a compromise is suspected. `AML.T0020 Poison Training Data` motivates the lineage-to-run join: if a specific upstream dataset is implicated, the warehouse can enumerate every run that transitively consumed it.

<!-- Local exercise context: The specific retention windows (365 days hot, 7 years archive), the 20-level depth bound on recursive lineage queries, the per-team row-level security on per-item fact rows, and the three committed analysis queries are illustrative defaults for an internal eval warehouse serving a medium ML org. Replace them with your organization's retention, audit, and access requirements before adopting. Sibling exercises: the registry whose artifact dimensions and lineage edges are the warehouse's source of truth is [exercise-01](../exercise-01-versioned-registry-design/SOLUTION.md); the orchestrator whose shard completions feed `on_shard_completed` is [exercise-02](../exercise-02-multi-runner-orchestration/SOLUTION.md); the cost controller whose cost rows reconcile against `fact_cost` is [exercise-03](../exercise-03-platform-cost-controls/SOLUTION.md); the CI pipeline whose per-commit runs land in the warehouse as `purpose='pr-gate'` is [exercise-05](../exercise-05-eval-in-ci-with-slo/SOLUTION.md). -->
