-- Migration 021: Add composite index on integration_credentials for active-credential lookups.
--
-- The existing indexes on migration 019 are:
--   idx_integration_credentials_user_id   ON integration_credentials(user_id)
--   idx_integration_credentials_provider  ON integration_credentials(provider)
--
-- The hot query path is "fetch active credential for a given user + provider" (e.g.
-- "give me the active Google Calendar credential for user X").  Without a composite
-- index the planner uses idx_integration_credentials_user_id to narrow to the user's
-- rows, then applies a filter on provider and is_active — linear in credentials-per-user.
--
-- This partial composite index turns that into an index-only scan.

CREATE INDEX IF NOT EXISTS idx_integration_credentials_user_provider_active
    ON integration_credentials(user_id, provider, is_active)
    WHERE is_active = TRUE;

-- Self-validating: confirm the index exists before proceeding.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'integration_credentials'
          AND indexname = 'idx_integration_credentials_user_provider_active'
    ) THEN
        RAISE EXCEPTION 'Migration 021 failed: index idx_integration_credentials_user_provider_active not created';
    END IF;
END $$;
