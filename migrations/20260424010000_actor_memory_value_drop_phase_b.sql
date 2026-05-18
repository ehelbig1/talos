-- Phase B (terminal) of `actor_memory` at-rest encryption.
--
-- Phase A landed 2026-04-23: added `value_enc` + `value_key_id`, dual-write
-- code, boot-time backfill. Verified: 0 rows with NULL value_enc and 0 rows
-- with non-NULL value remain (see `docs/security/agent-memory-encryption-plan.md`).
--
-- Phase B finalizes the encryption story:
--   1. DROP COLUMN value             — plaintext column no longer exists
--   2. SET NOT NULL on value_enc + value_key_id — every row is encrypted
--   3. DROP INDEX idx_actor_memory_needs_encryption — no longer needed
--
-- Rollback after this migration is destructive: there is no plaintext
-- column to read from. Restore from the dump captured before applying.

-- Defensive guard: refuse to drop `value` if any row still holds a
-- non-null plaintext payload (means backfill was skipped). Idempotent.
DO $$
DECLARE leftover BIGINT;
BEGIN
    SELECT COUNT(*) INTO leftover FROM actor_memory WHERE value IS NOT NULL;
    IF leftover > 0 THEN
        RAISE EXCEPTION
            'actor_memory still has % rows with plaintext value — '
            'run boot-time backfill first (see memory_crypto::backfill_unencrypted_rows)',
            leftover;
    END IF;

    SELECT COUNT(*) INTO leftover FROM actor_memory WHERE value_enc IS NULL;
    IF leftover > 0 THEN
        RAISE EXCEPTION
            'actor_memory has % rows with NULL value_enc — '
            'these rows would be unreadable after Phase B; '
            'investigate before re-running this migration',
            leftover;
    END IF;
END $$;

ALTER TABLE actor_memory
    DROP COLUMN value;

ALTER TABLE actor_memory
    ALTER COLUMN value_enc    SET NOT NULL,
    ALTER COLUMN value_key_id SET NOT NULL;

DROP INDEX IF EXISTS idx_actor_memory_needs_encryption;

COMMENT ON COLUMN actor_memory.value_enc IS
    'AES-256-GCM ciphertext of the JSON-serialized memory value. Encrypted via SecretsManager.encrypt_value (envelope encryption with the DEK in encryption_keys). Phase B: NOT NULL — every row is encrypted.';
