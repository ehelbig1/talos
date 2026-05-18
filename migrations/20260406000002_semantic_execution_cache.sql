-- Semantic execution cache for LLM workflow outputs.
-- Supports two lookup strategies:
--   1. Exact-match: (workflow_id, input_hash) — sub-millisecond via B-tree index.
--   2. Approximate nearest-neighbour: (workflow_id, input_embedding) — cosine
--      similarity via IVFFlat for semantically-equivalent inputs that differ
--      in whitespace, ordering, or minor phrasing.
--
-- The input_embedding column is nullable and written asynchronously after insert
-- so cache inserts never block on embedding inference.
--
-- TTL: expires_at = NULL means no expiry (pinned entries). The scheduler that
-- cleans up stale rows should filter using idx_exec_cache_expires.

CREATE TABLE IF NOT EXISTS semantic_execution_cache (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    workflow_id     UUID        NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    -- SHA-256 hex digest of the canonical (sorted-key) input JSON for exact-match.
    input_hash      TEXT        NOT NULL,
    -- 1536-dim embedding vector for semantic similarity search (nullable: written async).
    input_embedding vector(1536),
    -- Original input kept for display / debugging / re-embedding.
    input_json      JSONB       NOT NULL,
    -- Cached output returned to callers instead of re-running the workflow.
    output_json     JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL = no expiry (permanent cache entry).
    expires_at      TIMESTAMPTZ,
    -- Incremented each time this entry is served from cache.
    hit_count       INT         NOT NULL DEFAULT 0,

    PRIMARY KEY (id)
);

-- Primary lookup: exact-match on (workflow_id, input_hash).
-- Covers the fast path: hash the incoming input, check if it exists.
CREATE INDEX IF NOT EXISTS idx_exec_cache_workflow_hash
    ON semantic_execution_cache (workflow_id, input_hash);

-- Semantic search: IVFFlat cosine-distance index scoped to (workflow_id, input_embedding).
-- Only indexes rows that have been embedded (WHERE input_embedding IS NOT NULL).
-- lists=20 is appropriate for expected table sizes up to ~1M rows; raise to 50-100 for
-- larger datasets, and run ANALYZE after bulk inserts to keep the planner statistics fresh.
-- NOTE: IVFFlat requires rows to exist at CREATE INDEX time to build centroids. If the
-- table is empty, the index is created with 0 centroids and auto-rebuilds on first use.
CREATE INDEX IF NOT EXISTS idx_exec_cache_workflow_embedding
    ON semantic_execution_cache USING ivfflat (input_embedding vector_cosine_ops)
    WITH (lists = 20)
    WHERE input_embedding IS NOT NULL;

-- TTL cleanup: partial index on expires_at for efficient expired-row sweeps.
-- The background sweeper queries: DELETE FROM semantic_execution_cache
--   WHERE expires_at IS NOT NULL AND expires_at <= now()
-- and this index makes that scan O(expired) rather than O(table).
CREATE INDEX IF NOT EXISTS idx_exec_cache_expires
    ON semantic_execution_cache (expires_at)
    WHERE expires_at IS NOT NULL;

-- Active-entries index: supports listing/paginating permanent (non-expiring) cache entries
-- per workflow without a full table scan. Covers only pinned entries (expires_at IS NULL).
-- For entries with a future expires_at, use idx_exec_cache_expires combined with a
-- runtime filter — now() is not IMMUTABLE and cannot appear in an index predicate.
CREATE INDEX IF NOT EXISTS idx_exec_cache_active
    ON semantic_execution_cache (workflow_id, created_at DESC)
    WHERE expires_at IS NULL;
