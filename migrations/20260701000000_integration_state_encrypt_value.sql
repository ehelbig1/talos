-- integration_state: encrypt `value` at rest (per-context AEAD, v3 global / v4 per-org).
--
-- The primitive is advertised for durable "OAuth tokens + push-notification watch
-- secrets", but `value` was stored as plaintext JSONB. Today's reference
-- integrations (gmail/gcal) keep only non-secret metadata here, but the contract
-- must be encrypt-at-rest before a third integration stores an actual credential.
--
-- Strategy: add ciphertext columns; NEW writes go to `value_enc` (with plaintext
-- `value` NULL); reads decrypt `value_enc` when present and fall back to the legacy
-- plaintext `value` otherwise. No eager data migration — legacy rows re-encrypt
-- lazily on their next write (the reference integrations rewrite watch state on
-- every renewal, so the plaintext tail drains on its own).

ALTER TABLE integration_state
    ADD COLUMN IF NOT EXISTS value_enc    BYTEA,
    ADD COLUMN IF NOT EXISTS value_key_id UUID,
    ADD COLUMN IF NOT EXISTS value_format SMALLINT;

-- Encrypted rows carry ciphertext in value_enc + a NULL plaintext value; legacy
-- rows keep value plaintext with value_enc NULL. Relax the NOT NULL so an
-- encrypted row need not duplicate plaintext.
ALTER TABLE integration_state ALTER COLUMN value DROP NOT NULL;

-- Exactly one of (value, value_enc) is present per row (existing plaintext rows
-- satisfy this: value NOT NULL, value_enc NULL).
ALTER TABLE integration_state
    ADD CONSTRAINT integration_state_value_xor_enc
    CHECK ((value IS NOT NULL) <> (value_enc IS NOT NULL));

-- AEAD format for value_enc: per-context v3 (global DEK) or v4 (per-org DEK),
-- whichever SecretsManager returned. NULL for legacy plaintext rows. Widen the
-- IN(...) set here if a future format version is introduced.
ALTER TABLE integration_state
    ADD CONSTRAINT integration_state_value_format_valid
    CHECK (value_format IS NULL OR value_format IN (3, 4));

-- An encrypted row must carry BOTH its key id and format (needed to decrypt).
ALTER TABLE integration_state
    ADD CONSTRAINT integration_state_enc_columns_together
    CHECK (
        (value_enc IS NULL AND value_key_id IS NULL AND value_format IS NULL)
        OR (value_enc IS NOT NULL AND value_key_id IS NOT NULL AND value_format IS NOT NULL)
    );
