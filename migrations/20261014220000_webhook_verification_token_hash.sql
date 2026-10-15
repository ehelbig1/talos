-- A generic webhook's static verification token is kept as its SHA-256, not
-- in the clear (security review 2026-10-14, F-3).
--
-- `webhook_triggers.verification_token` held every static bearer token in the
-- fleet in plaintext, beside a `signing_secret_enc` that is envelope-encrypted.
-- The token is a bearer credential: it alone starts the owning workflow with a
-- body of the caller's choosing. A token needs no decryption to be checked,
-- only comparison, so it is stored the way approval-gate and action-link
-- tokens are: the hex SHA-256 of its UTF-8 bytes (the same digest as
-- `talos_text_util::sha256_hex`), compared in constant time on the hash.
--
-- This migration adds the hash and fills it from the plaintext; the next one
-- (20261014220100) drops the plaintext column. A token issued before this
-- migration keeps authenticating: its hash is what is compared now.
--
-- The column stays NULLABLE. A row whose backfill failed keeps a NULL hash,
-- and the webhook router refuses a static-token delivery to a row with no
-- hash (fail closed) — it never reads NULL as "no token, open webhook".

ALTER TABLE webhook_triggers ADD COLUMN IF NOT EXISTS verification_token_hash TEXT;

COMMENT ON COLUMN webhook_triggers.verification_token_hash IS
    'Hex SHA-256 of the static verification token (X-Verification-Token). '
    'The token itself is returned once, by the create, and never stored.';

-- The backfill is not an edit of the webhook, so it must not move
-- `updated_at` (update_updated_at_column treats every undeclared column as
-- user content). The trigger is switched off for this transaction only.
ALTER TABLE webhook_triggers DISABLE TRIGGER update_webhook_listeners_updated_at;

-- Per-row, each in its own implicit savepoint, so one bad row does not undo
-- the rest.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT id, verification_token
        FROM webhook_triggers
        WHERE verification_token_hash IS NULL
          AND verification_token IS NOT NULL
    LOOP
        BEGIN
            UPDATE webhook_triggers
               SET verification_token_hash =
                   encode(sha256(convert_to(r.verification_token, 'UTF8')), 'hex')
             WHERE id = r.id;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'webhook_triggers %: verification token hash backfill failed (%); '
                          'its static token will be refused until the webhook is recreated',
                          r.id, SQLERRM;
        END;
    END LOOP;
END $$;

ALTER TABLE webhook_triggers ENABLE TRIGGER update_webhook_listeners_updated_at;
