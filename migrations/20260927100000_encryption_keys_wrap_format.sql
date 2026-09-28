-- RFC 0013, phase 1+2: bind each wrapped DEK to the `encryption_keys` row that
-- stores it.
--
-- `encrypted_key` is the DEK wrapped by the KEK (AES-256-GCM, or Vault transit).
-- Until now the wrap carried no associated data, so a blob copied into another
-- row unwrapped cleanly under the KEK: org A's DEK planted in org B's active row
-- would seal every later org-B write under org A's key, and nothing would notice.
-- From this release every wrap binds `(id, org_id)` as AAD (see
-- `talos_secrets_manager::dek_wrap`), and a blob read under any other row's
-- identity fails to unwrap.
--
-- `wrap_format`:
--   1 = unbound (every row written before this release; read with an empty AAD,
--       which is byte-identical to the old wrap)
--   2 = bound to (id, org_id)
--
-- Existing rows stay 1 until the platform-admin `rebindDekWraps` mutation (or a
-- master-key rotation) rewraps them; `dekMigrationStatus` counts them as
-- `encryption_keys.wrap`. A later migration (RFC 0013 phase 3) will constrain
-- the column to 2 once every deployment has rebound, closing the downgrade in
-- which a writer marks a row 1 and plants an unbound blob.
--
-- Constant default + a CHECK that every existing row satisfies: a metadata-only
-- change, no table rewrite.
ALTER TABLE encryption_keys
    ADD COLUMN IF NOT EXISTS wrap_format smallint NOT NULL DEFAULT 1;

ALTER TABLE encryption_keys DROP CONSTRAINT IF EXISTS encryption_keys_wrap_format_check;
ALTER TABLE encryption_keys
    ADD CONSTRAINT encryption_keys_wrap_format_check CHECK (wrap_format IN (1, 2));
