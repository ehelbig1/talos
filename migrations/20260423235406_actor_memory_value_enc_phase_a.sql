-- Phase A of `actor_memory` at-rest encryption (additive, backwards-compatible).
--
-- See `docs/security/agent-memory-encryption-plan.md` for the full migration
-- sequence. This is migration A (the additive step) — it adds the columns
-- the dual-write code needs without touching the existing `value` column,
-- so a rollback is just "ignore the new columns".
--
-- Phase B (the terminal migration that drops `value`) is intentionally
-- NOT in this file — it MUST wait until:
--   1. Code change A (dual-write) has been deployed and observed stable
--   2. Backfill has run + been verified (zero rows with NULL value_enc)
--   3. Backup verification drill (operational-runbook.md §2.6) re-run
-- Combining A and B in one migration removes all rollback options.

ALTER TABLE actor_memory
    ADD COLUMN value_enc    BYTEA,
    ADD COLUMN value_key_id UUID REFERENCES encryption_keys(id) ON DELETE RESTRICT;

-- Partial index to make the backfill scan + the runtime "needs encryption"
-- check both fast. Once Phase B drops `value`, drop this index too.
CREATE INDEX idx_actor_memory_needs_encryption
    ON actor_memory(id)
    WHERE value_enc IS NULL;

COMMENT ON COLUMN actor_memory.value_enc IS
    'AES-256-GCM ciphertext of the JSON-serialized memory value. Encrypted via SecretsManager.encrypt_value (envelope encryption with the DEK in encryption_keys). NULL only during the Phase A → Phase B migration window for legacy rows whose plaintext still lives in `value`.';

COMMENT ON COLUMN actor_memory.value_key_id IS
    'FK to encryption_keys.id — the DEK that encrypted value_enc. Required for decryption via SecretsManager.decrypt_value_by_key. Set together with value_enc in the same write.';
