-- Drop the legacy plaintext signing_secret column from webhook_triggers.
--
-- The encrypted columns (signing_secret_enc BYTEA, signing_key_id UUID) were
-- added in migration 20260312000200_encrypt_webhook_signing_secrets.sql.
-- New webhook triggers created after that migration store only the encrypted
-- form; the plaintext column is now unused in the application.
--
-- Safety guard: abort if any row still has a plaintext secret without a
-- corresponding encrypted value (would indicate an incomplete backfill).
DO $$
DECLARE
    unencrypted_count bigint;
BEGIN
    SELECT COUNT(*) INTO unencrypted_count
    FROM webhook_triggers
    WHERE signing_secret IS NOT NULL
      AND (signing_secret_enc IS NULL OR signing_key_id IS NULL);

    IF unencrypted_count > 0 THEN
        RAISE EXCEPTION
            'Cannot drop plaintext signing_secret column: % row(s) have a plaintext '
            'secret without a corresponding encrypted value. '
            'Backfill these rows before running this migration.',
            unencrypted_count;
    END IF;
END $$;

ALTER TABLE webhook_triggers
    DROP COLUMN IF EXISTS signing_secret;
