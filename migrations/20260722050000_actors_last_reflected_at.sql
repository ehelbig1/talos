-- Phase 3 (reflection): fair rotation cursor for the autonomous memory-reflection sweep.
--
-- The reflection background loop scans a bounded number of active actors per
-- tick (MEMORY_REFLECTION_MAX_ACTORS_PER_TICK). As with the consolidation
-- sweep, an `ORDER BY id LIMIT N` scan would revisit the same lowest-id N
-- actors every tick and NEVER reach higher-id actors once the fleet exceeds N
-- — a silent coverage gap. This column is a least-recently-swept cursor: the
-- scan orders by `last_reflected_at ASC NULLS FIRST` (never-reflected actors
-- first), and the loop stamps every actor it examined (reflected OR skipped)
-- with now() so the sweep advances through the whole fleet fairly.
--
-- Reflection uses its OWN cursor (separate from consolidation's
-- `last_consolidated_at`) because the two loops run on independent cadences
-- and must not couple rotation: an actor consolidated this tick should still
-- be reachable by reflection next tick, and vice-versa.
--
-- NULLable with NO default: NULL = "never reflected" and must sort FIRST,
-- which a non-null default would defeat. Idempotent; no CONCURRENTLY (sqlx tx).

ALTER TABLE actors ADD COLUMN IF NOT EXISTS last_reflected_at timestamptz;

-- The sweep's ordering scan: least-recently-reflected active actors first.
CREATE INDEX IF NOT EXISTS idx_actors_reflection_cursor
    ON actors (last_reflected_at ASC NULLS FIRST)
    WHERE status = 'active';
