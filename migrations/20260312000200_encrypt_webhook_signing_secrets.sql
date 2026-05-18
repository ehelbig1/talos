-- Encrypt webhook signing secrets at rest using envelope encryption (AES-256-GCM).
-- Follows the same pattern as gmail_integrations (migration 020).
--
-- New columns:
--   signing_secret_enc  – nonce(12) || ciphertext (BYTEA)
--   signing_key_id      – FK to encryption_keys.id used for decryption
--
-- The legacy plaintext `signing_secret` column is kept temporarily for the
-- backfill migration step.  A follow-up migration will drop it after all rows
-- have been re-encrypted.

ALTER TABLE webhook_triggers
    ADD COLUMN IF NOT EXISTS signing_secret_enc BYTEA,
    ADD COLUMN IF NOT EXISTS signing_key_id UUID REFERENCES encryption_keys(id);

-- Backfill: handled at application startup (SecretsManager encrypts existing
-- plaintext values and writes to the new columns, then NULLs the old column).
-- This avoids running crypto in a migration where SecretsManager is unavailable.
