-- Per-org root DEKs, per-table cutover: users.totp_secret.
--
-- talos-totp-2fa now writes format v4 (per-context key derived from the user's
-- PERSONAL-org root DEK) instead of v3 (global DEK). Widen the format CHECK to
-- admit 4. v0/v1/v3 rows keep decrypting unchanged (decrypt_versioned routes v4
-- through the same derived path as v3). No data change — existing rows migrate
-- lazily on the next 2FA re-enable, or via the later per-org re-encrypt sweep.

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_totp_secret_format_known;
ALTER TABLE users
    ADD CONSTRAINT users_totp_secret_format_known
    CHECK (totp_secret_format IN (0, 1, 3, 4));

COMMENT ON COLUMN users.totp_secret_format IS
    'AES-GCM AAD version for totp_secret. 0=legacy no-AAD, 1=AAD-bound to '
    'users.id, 3=AAD-bound + per-context-derived key (global DEK), 4=same but '
    'derived from the user''s per-ORG root DEK. See '
    'talos_secrets_manager::AAD_FORMAT_V4_ORG_DERIVED.';
