-- API keys are verified by a constant-time compare of the key's SHA-256
-- digest instead of bcrypt on every request (the key is 256 random bits, so a
-- slow hash protects nothing and cost ~100 ms of CPU per authenticated call).
-- NULL on rows minted before this migration: those are bcrypt-verified once
-- and upgraded in place by `ApiKeyService::validate_key`. No backfill is
-- possible — the plaintext key is never stored.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_digest text;

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_key_digest
    ON api_keys (key_digest)
    WHERE key_digest IS NOT NULL;
