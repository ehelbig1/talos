-- Migration 016: Google Calendar watch channel improvements
--
-- 1. Prevent duplicate active watch channels for the same (integration, calendar) pair.
--    If two active channels for the same calendar exist, only the most recently
--    created one is kept active; older duplicates are deactivated first.
--
-- 2. Add a partial unique index on (integration_id, calendar_id) WHERE is_active = TRUE
--    so that database-level enforcement prevents future duplicates.

-- ============================================================
-- Deactivate any existing duplicate active watch channels,
-- keeping only the most recently created one per (integration, calendar).
-- ============================================================
UPDATE google_calendar_watch_channels
SET is_active = false
WHERE id NOT IN (
    SELECT DISTINCT ON (integration_id, calendar_id)
        id
    FROM google_calendar_watch_channels
    WHERE is_active = true
    ORDER BY integration_id, calendar_id, created_at DESC
);

-- ============================================================
-- Enforce uniqueness at the database level (active channels only).
-- Partial unique index: allows multiple *inactive* rows for history
-- while preventing two *active* channels for the same calendar.
-- ============================================================
CREATE UNIQUE INDEX IF NOT EXISTS idx_watch_channels_active_unique
    ON google_calendar_watch_channels (integration_id, calendar_id)
    WHERE is_active = TRUE;

-- ============================================================
-- Self-validate
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'google_calendar_watch_channels'
          AND indexname = 'idx_watch_channels_active_unique'
    ) THEN
        RAISE EXCEPTION 'Migration 016 failed: idx_watch_channels_active_unique index not found';
    END IF;

    RAISE NOTICE 'Migration 016 completed successfully: duplicate active watch channels prevented';
END $$;
