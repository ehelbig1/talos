-- Migration 036: Drop plaintext token columns

ALTER TABLE slack_integrations
    DROP COLUMN IF EXISTS bot_token,
    DROP COLUMN IF EXISTS access_token;

ALTER TABLE gmail_integrations
    DROP COLUMN IF EXISTS access_token,
    DROP COLUMN IF EXISTS refresh_token;

-- Self-validating
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'slack_integrations' AND column_name = 'bot_token'
    ) THEN
        RAISE EXCEPTION 'Migration failed: slack_integrations.bot_token still exists';
    END IF;
END $$;
