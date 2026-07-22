-- Phase 3b: fair rotation cursor for the autonomous memory-consolidation sweep.
--
-- The background loop scans a bounded number of active actors per tick
-- (MEMORY_CONSOLIDATION_MAX_ACTORS_PER_TICK). Without a rotation cursor an
-- `ORDER BY id LIMIT N` scan would revisit the same lowest-id N actors every
-- tick and NEVER reach higher-id actors once the fleet exceeds N — a silent
-- coverage gap. This column is a least-recently-swept cursor: the scan orders
-- by `last_consolidated_at ASC NULLS FIRST` (never-swept actors first), and the
-- loop stamps every actor it processed (consolidated OR skipped) with now() so
-- the sweep advances through the whole fleet fairly. Same pattern talos-ml's
-- digest / lifecycle jobs use.
--
-- NULLable with NO default: NULL = "never swept" and must sort FIRST, which a
-- non-null default would defeat. Idempotent; no CONCURRENTLY (sqlx tx).

ALTER TABLE actors ADD COLUMN IF NOT EXISTS last_consolidated_at timestamptz;

-- The sweep's ordering scan: least-recently-consolidated active actors first.
CREATE INDEX IF NOT EXISTS idx_actors_consolidation_cursor
    ON actors (last_consolidated_at ASC NULLS FIRST)
    WHERE status = 'active';
