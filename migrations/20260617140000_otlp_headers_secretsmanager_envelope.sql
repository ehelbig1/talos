-- OTLP auth-header encryption: migrate from the bespoke env-master-key HKDF
-- scheme to the canonical SecretsManager envelope (KEK-backed DEK + per-context
-- HKDF subkey + AAD). The motivation is decoupling authenticated audit-log
-- streaming from TALOS_MASTER_KEY so a Vault-only deployment
-- (KEK_PROVIDER=vault, KEK_DISABLE_LEGACY=true, master key absent from env) can
-- still encrypt the per-tenant OTLP auth headers — the SecretsManager DEK is
-- unwrapped through whatever KekProvider is configured (env OR Vault transit).
--
-- Two new columns mirror the (key_id, format) pairing every other AAD-bound
-- column uses (workflow_executions.output_enc_key_id/output_data_format,
-- secrets.encryption_key_id/encryption_format_version, etc.):
--
--   * auth_headers_enc_key_id — the encryption_keys.id of the DEK the v3
--     envelope used. NULL for legacy rows written by the env-master-key scheme.
--   * auth_headers_format     — AAD format version. 0 = legacy env-key HKDF
--     scheme (the value existing rows take by default); 3 = SecretsManager v3
--     per-context-derived envelope.
--
-- Read-path dispatch (talos-audit-ledger OTLPCache::get_tracer):
--   * auth_headers_enc_key_id IS NULL  → legacy row → decrypt via the
--     env-master-key HKDF helper (decrypt_otlp_auth_headers). Still needs
--     TALOS_MASTER_KEY, so legacy rows must be re-saved before the env key can
--     be dropped on a Vault-only deployment.
--   * auth_headers_enc_key_id IS NOT NULL → SecretsManager v3 → decrypt via
--     decrypt_versioned(key_id, blob, aad = user_id bytes, format).
--
-- New writes always populate both columns, so the env-key dependency is
-- self-healing: every settings re-save migrates that tenant's row to the v3
-- envelope. The v3 nonce is embedded in the blob (12-byte prefix) stored in
-- auth_headers_encrypted; auth_headers_nonce stays populated only on legacy rows.

ALTER TABLE user_audit_settings
    ADD COLUMN IF NOT EXISTS auth_headers_enc_key_id UUID,
    ADD COLUMN IF NOT EXISTS auth_headers_format SMALLINT NOT NULL DEFAULT 0;
