-- Adaptive per-actor memory ranking — Phase 2: fair rotation cursor for the
-- per-actor rank-training sweep.
--
-- The training loop fits at most MAX_ACTORS_PER_TICK actors per tick. Without a
-- rotation cursor an `ORDER BY id LIMIT N` scan would only ever train the
-- lowest-N-by-UUID active actors — every other actor would NEVER get a model
-- and silently stay on global weights forever (safe, but the adaptive feature
-- would be a no-op for most of a large fleet). This column is a least-recently-
-- trained cursor: the scan orders by `last_rank_trained_at ASC NULLS FIRST`
-- (never-trained actors first) and the loop stamps every actor it examined so
-- the sweep advances through the whole fleet. Same pattern as
-- `last_consolidated_at` (Phase-3b consolidation rotation).
--
-- NULLable, no default (NULL = "never trained", must sort FIRST). Idempotent;
-- no CONCURRENTLY (sqlx tx).

ALTER TABLE actors ADD COLUMN IF NOT EXISTS last_rank_trained_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_actors_rank_training_cursor
    ON actors (last_rank_trained_at ASC NULLS FIRST)
    WHERE status = 'active';
