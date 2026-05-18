-- Migration 019: Unified OAuth credential storage
-- Stores encrypted OAuth tokens as secrets (via SecretsManager) with metadata
-- tracked in integration_credentials for efficient lookups and refresh decisions.
--
-- Design: tokens live in the secrets table (envelope-encrypted); this table
-- holds only non-sensitive metadata (secret paths, expiry, scope) and acts
-- as the index for generic OAuth management queries.

CREATE TABLE IF NOT EXISTS integration_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,          -- 'google_calendar', 'gmail', 'slack'
    provider_key VARCHAR(255) NOT NULL,     -- oauth_account_id, email, team_id, etc.
    access_token_secret_path TEXT,          -- key_path in secrets table
    refresh_token_secret_path TEXT,         -- key_path in secrets table (nullable)
    token_expires_at TIMESTAMPTZ,           -- plaintext expiry (not sensitive)
    scope TEXT,                             -- comma-separated OAuth scopes granted
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, provider, provider_key)
);

CREATE INDEX IF NOT EXISTS idx_integration_credentials_user_id
    ON integration_credentials(user_id);

CREATE INDEX IF NOT EXISTS idx_integration_credentials_provider
    ON integration_credentials(provider);

-- Self-validate: ensure the table exists with required columns
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'integration_credentials'
    ) THEN
        RAISE EXCEPTION 'Migration 019 failed: integration_credentials table not created';
    END IF;
END $$;
