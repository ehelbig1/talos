-- Phase 3 of KEK→KMS: add a second wrapping slot on `encryption_keys`
-- so the rewrap migration can run side-by-side with live traffic.
--
-- See `docs/security/kek-to-kms-plan.md` for the full migration plan.
-- This is the additive step — purely reversible. Phase 4 (reader cutover)
-- and Phase 5 (terminal: drop legacy column, NOT NULL on v2) ship later.
--
-- Wire format of `encrypted_key_v2` is provider-defined (opaque BYTEA):
--   - EnvKekProvider:    12-byte nonce || AES-256-GCM ciphertext
--   - VaultTransitProvider: UTF-8 bytes of `vault:vN:<base64>` string
-- The `KekProvider` trait round-trips bytes opaquely; nothing in the
-- DB layer inspects them.
--
-- Nullable during the soak window: rows that haven't been rewrapped yet
-- carry NULL in v2. Phase 5 enforces NOT NULL after backfill verification.

ALTER TABLE encryption_keys
    ADD COLUMN encrypted_key_v2 BYTEA;

-- Partial index over rows that still need rewrapping. Keeps the
-- "anything left to do?" probe O(remaining), not O(total). Drop in
-- Phase 5 alongside the legacy column.
CREATE INDEX idx_encryption_keys_needs_rewrap
    ON encryption_keys(id)
    WHERE encrypted_key_v2 IS NULL;

COMMENT ON COLUMN encryption_keys.encrypted_key_v2 IS
    'Phase 3 dual-wrap slot — DEK wrapped by the new KEK provider (Vault transit). Wire format is provider-defined and opaque to the DB layer. NULL until the rewrap migration runs; NOT NULL after Phase 5.';
