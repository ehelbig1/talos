-- Migration: Verify all plaintext tokens have been encrypted, then drop plaintext columns
--
-- SAFETY CHECK: This migration refuses to run if any row still has a non-empty
-- plaintext token without a corresponding encrypted value.  This prevents data
-- loss if the background encryption back-fill has not yet completed.
--
-- NOTE: Migration 036 may have already dropped some of these columns.
-- All checks are guarded with column-existence tests so this migration
-- is idempotent regardless of prior state.

-- ============================================================================
-- Step 1: Pre-drop verification – abort if any plaintext-only tokens remain
-- ============================================================================

-- Slack: verify bot_token is encrypted wherever it was non-empty
DO $$
BEGIN
    -- Only check if the column still exists (036 may have already dropped it)
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'slack_integrations' AND column_name = 'bot_token'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM slack_integrations
            WHERE bot_token IS NOT NULL
              AND bot_token <> ''
              AND bot_token_enc IS NULL
        ) THEN
            RAISE EXCEPTION
                'Aborting migration: slack_integrations has rows with plaintext bot_token but no bot_token_enc. '
                'Run the token encryption back-fill before retrying.';
        END IF;
    END IF;
END $$;

-- Slack: verify access_token is encrypted wherever it was non-empty
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'slack_integrations' AND column_name = 'access_token'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM slack_integrations
            WHERE access_token IS NOT NULL
              AND access_token <> ''
              AND access_token_enc IS NULL
        ) THEN
            RAISE EXCEPTION
                'Aborting migration: slack_integrations has rows with plaintext access_token but no access_token_enc. '
                'Run the token encryption back-fill before retrying.';
        END IF;
    END IF;
END $$;

-- Gmail: verify access_token is encrypted wherever it was non-empty
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'gmail_integrations' AND column_name = 'access_token'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM gmail_integrations
            WHERE access_token IS NOT NULL
              AND access_token <> ''
              AND access_token_enc IS NULL
        ) THEN
            RAISE EXCEPTION
                'Aborting migration: gmail_integrations has rows with plaintext access_token but no access_token_enc. '
                'Run the token encryption back-fill before retrying.';
        END IF;
    END IF;
END $$;

-- Gmail: verify refresh_token is encrypted wherever it was non-empty
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'gmail_integrations' AND column_name = 'refresh_token'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM gmail_integrations
            WHERE refresh_token IS NOT NULL
              AND refresh_token <> ''
              AND refresh_token_enc IS NULL
        ) THEN
            RAISE EXCEPTION
                'Aborting migration: gmail_integrations has rows with plaintext refresh_token but no refresh_token_enc. '
                'Run the token encryption back-fill before retrying.';
        END IF;
    END IF;
END $$;

-- Google Calendar: verify access_token is encrypted wherever it was non-empty
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'google_calendar_integrations' AND column_name = 'access_token'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM google_calendar_integrations
            WHERE access_token IS NOT NULL
              AND access_token <> ''
              AND access_token_enc IS NULL
        ) THEN
            RAISE EXCEPTION
                'Aborting migration: google_calendar_integrations has rows with plaintext access_token but no access_token_enc. '
                'Run the token encryption back-fill before retrying.';
        END IF;
    END IF;
END $$;

-- Google Calendar: verify refresh_token is encrypted wherever it was non-empty
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'google_calendar_integrations' AND column_name = 'refresh_token'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM google_calendar_integrations
            WHERE refresh_token IS NOT NULL
              AND refresh_token <> ''
              AND refresh_token_enc IS NULL
        ) THEN
            RAISE EXCEPTION
                'Aborting migration: google_calendar_integrations has rows with plaintext refresh_token but no refresh_token_enc. '
                'Run the token encryption back-fill before retrying.';
        END IF;
    END IF;
END $$;

-- ============================================================================
-- Step 2: All rows verified – safely drop the plaintext columns
-- ============================================================================

ALTER TABLE slack_integrations
    DROP COLUMN IF EXISTS bot_token,
    DROP COLUMN IF EXISTS access_token;

ALTER TABLE gmail_integrations
    DROP COLUMN IF EXISTS access_token,
    DROP COLUMN IF EXISTS refresh_token;

ALTER TABLE google_calendar_integrations
    DROP COLUMN IF EXISTS access_token,
    DROP COLUMN IF EXISTS refresh_token;

-- ============================================================================
-- Step 3: Post-drop validation – confirm columns are gone
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE (table_name = 'slack_integrations'              AND column_name IN ('bot_token', 'access_token'))
           OR (table_name = 'gmail_integrations'              AND column_name IN ('access_token', 'refresh_token'))
           OR (table_name = 'google_calendar_integrations'    AND column_name IN ('access_token', 'refresh_token'))
    ) THEN
        RAISE EXCEPTION 'Migration failed: one or more plaintext token columns still exist after DROP';
    END IF;
END $$;
