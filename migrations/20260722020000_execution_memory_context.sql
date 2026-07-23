-- Adaptive per-actor memory ranking — Phase 1: provenance substrate.
--
-- Links each actor-bound execution that injected `__actor_context__` to the
-- memory KEYS that were in that context, plus the per-memory ranking-feature
-- snapshot captured at pack time (relevance / recency / importance /
-- access_boost / fused_score / rank). This is the training substrate a later
-- phase joins to execution OUTCOME (`judge_scores`, `workflow_executions.status`)
-- to LEARN which memories lead to good results. This phase only OBSERVES —
-- ranking behaviour is unchanged.
--
-- Privacy posture: stores memory KEYS + numeric feature signals ONLY — never
-- memory VALUES. Every row carries `actor_id` (tenancy), and reads are
-- `WHERE actor_id = $1`. Retention-bounded via a periodic sweep
-- (`sweep_execution_memory_context`).
--
-- No FKs on execution_id / actor_id: the provenance write is a best-effort,
-- fire-and-forget spawn that runs BEFORE the execution row is guaranteed
-- durable (execution_id is minted, then context is packed, then the row is
-- INSERTed under the concurrency limit — which may reject). Orphan rows (the
-- execution INSERT later failed) simply never join in the labeled-example
-- query and age out via retention — harmless. Same FK-free rationale as
-- `judge_scores`.
CREATE TABLE IF NOT EXISTS execution_memory_context (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    memory_key text NOT NULL,
    -- per-memory ranking-feature snapshot at pack time (the model's features):
    relevance real NOT NULL,
    recency real NOT NULL,          -- recency_component value in [0,1]
    importance real NOT NULL,       -- importance(c, access_weight) value in [0,1]
    access_boost real,              -- nullable (None for rows with no access signal)
    fused_score real NOT NULL,
    rank integer NOT NULL,          -- 0-based position in the packed set
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Serves the Phase-2 labeled-example query's outward join key (given a
-- provenance row, find its execution's judge score) and a reverse
-- "which memories were in execution X" lookup.
CREATE INDEX IF NOT EXISTS idx_emc_execution ON execution_memory_context (execution_id);
-- Serves the actor-scoped training-example read (`WHERE actor_id=$1 ORDER BY created_at DESC`).
CREATE INDEX IF NOT EXISTS idx_emc_actor_created ON execution_memory_context (actor_id, created_at);
-- Serves the retention sweep: `DELETE WHERE created_at < now() - interval`.
-- The composite `(actor_id, created_at)` index above can't serve this range
-- scan (leading column is actor_id), so a standalone created_at index keeps
-- the hourly sweep from seq-scanning a fast-growing table.
CREATE INDEX IF NOT EXISTS idx_emc_created ON execution_memory_context (created_at);
