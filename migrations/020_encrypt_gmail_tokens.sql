-- Migration 020: Create gmail_integrations table with encrypted token support
--
-- The gmail_integrations table was inadvertently omitted from earlier migrations.
-- This migration creates it from scratch with encryption columns included from day one,
-- using ADD COLUMN IF NOT EXISTS for each encryption field so the migration is also safe
-- to run against any database that already has the base table.
--
-- Encryption columns:
--   access_token_enc / refresh_token_enc: AES-256-GCM (nonce || ciphertext)
--   token_key_id: references encryption_keys.id for deterministic DEK lookup after rotation

CREATE TABLE IF NOT EXISTS gmail_integrations (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_address    TEXT        NOT NULL,
    account_name     TEXT,
    -- Plaintext tokens: kept for backward-compatibility during the transition period.
    -- Prefer access_token_enc / refresh_token_enc when present.
    access_token     TEXT        NOT NULL DEFAULT '',
    refresh_token    TEXT,
    token_expires_at TIMESTAMPTZ,
    scope            TEXT,
    is_active        BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at     TIMESTAMPTZ,

    -- Encrypted token columns (AES-256-GCM envelope encryption)
    access_token_enc  BYTEA,
    refresh_token_enc BYTEA,
    token_key_id      UUID REFERENCES encryption_keys(id),

    UNIQUE (user_id, email_address)
);

CREATE INDEX IF NOT EXISTS idx_gmail_integrations_user_id
    ON gmail_integrations(user_id);

CREATE INDEX IF NOT EXISTS idx_gmail_integrations_user_active
    ON gmail_integrations(user_id, is_active);

-- In case the table already existed without encryption columns, add them idempotently.
ALTER TABLE gmail_integrations
    ADD COLUMN IF NOT EXISTS access_token_enc  BYTEA,
    ADD COLUMN IF NOT EXISTS refresh_token_enc BYTEA,
    ADD COLUMN IF NOT EXISTS token_key_id      UUID REFERENCES encryption_keys(id);

-- Self-validate
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name  = 'gmail_integrations'
          AND column_name = 'access_token_enc'
    ) THEN
        RAISE EXCEPTION 'Migration 020 failed: access_token_enc column not present';
    END IF;
END $$;
