-- Migration 018: Encrypt Slack integration tokens at rest
--
-- Adds encrypted BYTEA columns for bot_token and access_token so that OAuth
-- tokens are encrypted with the Talos DEK (AES-256-GCM) before being stored.
-- The new columns are nullable; the application writes the encrypted form on the
-- next token save and reads the encrypted form when present.  A future migration
-- can drop the plaintext columns once all rows have been re-encrypted.

ALTER TABLE slack_integrations
    ADD COLUMN IF NOT EXISTS bot_token_enc    BYTEA,
    ADD COLUMN IF NOT EXISTS access_token_enc BYTEA;

COMMENT ON COLUMN slack_integrations.bot_token_enc IS
    'AES-256-GCM encrypted bot token (format: 16-byte key_id || 12-byte nonce || ciphertext). '
    'Supersedes the plaintext bot_token column.';

COMMENT ON COLUMN slack_integrations.access_token_enc IS
    'AES-256-GCM encrypted user access token. Supersedes the plaintext access_token column.';

-- Self-validating: ensure new columns exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'slack_integrations'
          AND column_name = 'bot_token_enc'
    ) THEN
        RAISE EXCEPTION 'Migration 018 failed: bot_token_enc column was not created';
    END IF;
END $$;
