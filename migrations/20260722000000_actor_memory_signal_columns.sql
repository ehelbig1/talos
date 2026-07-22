-- Phase 3a: durable memory signals feeding the fused actor-context ranker.
--
-- Adds three plaintext signal columns alongside the existing encrypted
-- value/embedding/metadata columns (the value_enc/value_key_id/value_format
-- decrypt path is untouched — these are additive signals only):
--
--   * importance      — write-time importance score in [0,1] (memory-type base
--                       blended 50/50 with metadata.importance). NULLable:
--                       NULL means "not yet scored" (older rows written before
--                       this migration); the ranker treats NULL as an absent
--                       hint and falls back to metadata.importance. Deliberately
--                       NO NOT NULL default — a synthetic 0/0.5 default would be
--                       indistinguishable from a real score.
--   * access_count    — number of times this row has been packed into an
--                       injected __actor_context__ set (recall-path fire-and-
--                       forget bump). Feeds the access-frequency boost in
--                       importance().
--   * last_accessed_at — timestamp of the most recent context injection; NULL
--                        until first accessed. Substrate for Phase 3b
--                        consolidation candidate scans (stale + low-importance).
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS); no
-- CONCURRENTLY (sqlx runs migrations inside a transaction).

ALTER TABLE actor_memory ADD COLUMN IF NOT EXISTS importance real;
ALTER TABLE actor_memory ADD COLUMN IF NOT EXISTS access_count integer NOT NULL DEFAULT 0;
ALTER TABLE actor_memory ADD COLUMN IF NOT EXISTS last_accessed_at timestamptz;

-- Supports Phase 3b's consolidation candidate scan: for a given actor, find
-- low-importance / cold rows ordered by importance + last_accessed_at.
CREATE INDEX IF NOT EXISTS idx_actor_memory_signals
    ON actor_memory (actor_id, importance, last_accessed_at);
