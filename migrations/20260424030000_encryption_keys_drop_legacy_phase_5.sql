-- Phase 5 (terminal) of KEK→KMS: drop the legacy `encrypted_key`
-- column, rename `encrypted_key_v2` to take its place, enforce NOT NULL.
--
-- See `docs/security/kek-to-kms-plan.md` for the full migration plan.
--
-- Prerequisites — caller MUST have run:
--   1. `cargo run --example verify_v2_decryptable -p controller` with
--      KEK_PROVIDER=vault, exit code 0. This proves every row's
--      encrypted_key_v2 actually decrypts with the active Vault provider.
--   2. A backup of the database captured AFTER Phase 3 rewrap and
--      BEFORE this migration (so a Vault-side disaster within the soak
--      window still has a recovery path).
--
-- This migration is irreversible: the legacy ciphertext is gone after
-- DROP COLUMN. Restore-from-dump is the only recovery path.

-- Defensive guards: refuse to drop the legacy column if any row would
-- become orphaned. Mirrors the actor_memory Phase B pattern.
DO $$
DECLARE leftover BIGINT;
BEGIN
    SELECT COUNT(*) INTO leftover FROM encryption_keys WHERE encrypted_key_v2 IS NULL;
    IF leftover > 0 THEN
        RAISE EXCEPTION
            'Phase 5 abort: % rows still have NULL encrypted_key_v2. '
            'Run `rewrap_deks_to_vault` until count reaches zero, then re-run.',
            leftover;
    END IF;

    SELECT COUNT(*) INTO leftover FROM encryption_keys
        WHERE octet_length(encrypted_key_v2) = 0;
    IF leftover > 0 THEN
        RAISE EXCEPTION
            'Phase 5 abort: % rows have empty encrypted_key_v2. '
            'Investigate these rows before re-running.',
            leftover;
    END IF;
END $$;

-- The legacy v1 ciphertext is no longer referenced by any code path.
ALTER TABLE encryption_keys DROP COLUMN encrypted_key;

-- Promote v2 into the canonical column name. Codepath collapses back
-- to single-column SQL after this rename.
ALTER TABLE encryption_keys RENAME COLUMN encrypted_key_v2 TO encrypted_key;

-- Phase 4 already populated v2 for every row, so NOT NULL is safe now.
ALTER TABLE encryption_keys ALTER COLUMN encrypted_key SET NOT NULL;

-- The partial-index over needs-rewrap rows is no longer relevant.
DROP INDEX IF EXISTS idx_encryption_keys_needs_rewrap;

COMMENT ON COLUMN encryption_keys.encrypted_key IS
    'DEK ciphertext, wire format defined by the active KekProvider (Vault transit by default after Phase 5). NOT NULL: every row must be decryptable.';
