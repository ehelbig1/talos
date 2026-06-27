-- Per-org root DEKs, per-table cutover: secrets.encrypted_value.
--
-- SecretsManager now writes format v4 (per-context key derived from the row's
-- ORG root DEK) for org-scoped secrets (org_id IS NOT NULL); personal/global
-- secrets (org_id NULL) stay v3 under the global DEK. Widen the format CHECK to
-- admit 4. v0/v1/v3 rows keep decrypting unchanged (decrypt_secret_record routes
-- v4 through the same per-context derived path as v3). Existing rows migrate
-- lazily on the next write (create/update/upsert/rotate). The GLOBAL re-encrypt
-- sweep (re_encrypt_secrets) explicitly skips v4 rows so it can't downgrade them.

ALTER TABLE secrets
    DROP CONSTRAINT IF EXISTS secrets_encryption_format_version_known;
ALTER TABLE secrets
    ADD CONSTRAINT secrets_encryption_format_version_known
    CHECK (encryption_format_version IN (0, 1, 3, 4));

COMMENT ON COLUMN secrets.encryption_format_version IS
    'AES-GCM AAD version for encrypted_value. 0=legacy no-AAD, 1=AAD-bound to '
    'secrets.id, 3=AAD-bound + per-context-derived key (global DEK), 4=same but '
    'derived from the row''s per-ORG root DEK (org_id IS NOT NULL). See '
    'talos_secrets_manager::AAD_FORMAT_V4_ORG_DERIVED.';
