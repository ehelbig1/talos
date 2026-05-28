-- AEAD AAD-binding sweep: extend the MCP-T2-N1 `secrets` table model
-- to every other table that stores AES-GCM ciphertext via
-- `SecretsManager::encrypt_value`. Before this migration the legacy
-- v0 ciphertexts (no AAD) are mutually decryptable under the same
-- `encryption_key_id`, so an attacker with DB-write capability can
-- swap ciphertexts between rows of the same table (silent 2FA bypass,
-- silent webhook-signing-secret forgery, etc.).
--
-- The fix mirrors the `secrets.encryption_format_version` pattern:
--   * v0 = legacy, no AAD; decrypts via `decrypt_value_by_key`.
--   * v1 = AAD-bound to the row's primary key bytes; decrypts via
--     `decrypt_value_by_key_with_aad(key_id, encrypted, row_id_bytes)`.
--
-- The column is NOT NULL with DEFAULT 0 so existing rows continue
-- working through the v0 path. New writes (after the code change ships)
-- set the column to 1 and pass the row id as AAD. Operator-driven
-- re-encrypt routines lift v0 rows to v1 over time.
--
-- CHECK constraints clamp the column to known versions so an attacker
-- with table-write access can't set 99 and bypass dispatch.

-- ── 1. users.totp_secret ─────────────────────────────────────────────
-- The 2FA shared secret. AAD = users.id bytes. Highest-impact target
-- pre-fix: swap victim's totp_secret onto attacker's row and you
-- silently bypass victim's 2FA.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_format SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_totp_secret_format_known;
ALTER TABLE users
    ADD CONSTRAINT users_totp_secret_format_known
    CHECK (totp_secret_format IN (0, 1));
COMMENT ON COLUMN users.totp_secret_format IS
    'AES-GCM AAD version for totp_secret. 0=legacy no-AAD, 1=AAD-bound to users.id bytes. See talos_secrets_manager::AAD_FORMAT_V1.';

-- ── 2. webhook_triggers.signing_secret_enc ───────────────────────────
-- HMAC signing secret for inbound webhooks. AAD = webhook_triggers.id.
-- Pre-fix swap → attacker forges webhook payloads under victim's
-- HMAC.
ALTER TABLE webhook_triggers
    ADD COLUMN IF NOT EXISTS signing_secret_format SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE webhook_triggers
    DROP CONSTRAINT IF EXISTS webhook_triggers_signing_secret_format_known;
ALTER TABLE webhook_triggers
    ADD CONSTRAINT webhook_triggers_signing_secret_format_known
    CHECK (signing_secret_format IN (0, 1));
COMMENT ON COLUMN webhook_triggers.signing_secret_format IS
    'AES-GCM AAD version for signing_secret_enc. 0=legacy no-AAD, 1=AAD-bound to webhook_triggers.id bytes.';

-- (3. user_audit_settings.auth_headers_encrypted — NOT migrated in this
--  sweep. The matching decrypt path in `talos-audit-ledger` uses
--  TALOS_MASTER_KEY directly, NOT SecretsManager DEKs — a pre-existing
--  key-chain inconsistency. Adding AAD on the encrypt side wouldn't
--  reach the read path; both sides need to be realigned onto
--  SecretsManager before AAD can flow end-to-end. Tracked separately.)

-- ── 4. workflow_executions.output_data_enc ───────────────────────────
-- Execution output payload (may carry PII, secrets, etc.). AAD =
-- workflow_executions.id bytes.
ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS output_data_format SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE workflow_executions
    DROP CONSTRAINT IF EXISTS workflow_executions_output_data_format_known;
ALTER TABLE workflow_executions
    ADD CONSTRAINT workflow_executions_output_data_format_known
    CHECK (output_data_format IN (0, 1));
COMMENT ON COLUMN workflow_executions.output_data_format IS
    'AES-GCM AAD version for output_data_enc. 0=legacy no-AAD, 1=AAD-bound to workflow_executions.id bytes.';

-- ── 5. module_executions payload columns ─────────────────────────────
-- input_data_enc + output_data_enc + trigger_metadata_enc share the
-- same key_id (payload_enc_key_id) and AAD (module_executions.id).
ALTER TABLE module_executions
    ADD COLUMN IF NOT EXISTS payload_format SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE module_executions
    DROP CONSTRAINT IF EXISTS module_executions_payload_format_known;
ALTER TABLE module_executions
    ADD CONSTRAINT module_executions_payload_format_known
    CHECK (payload_format IN (0, 1));
COMMENT ON COLUMN module_executions.payload_format IS
    'AES-GCM AAD version for {input,output,trigger_metadata}_enc. 0=legacy no-AAD, 1=AAD-bound to module_executions.id bytes.';

-- ── 6. actor_memory.value_enc ────────────────────────────────────────
-- Encrypted memory rows. AAD = actor_memory.id bytes. Lower exploit
-- value than 2FA/webhook (actor_memory's content is workflow-domain
-- data) but the swap-resistance property is uniform.
ALTER TABLE actor_memory
    ADD COLUMN IF NOT EXISTS value_format SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE actor_memory
    DROP CONSTRAINT IF EXISTS actor_memory_value_format_known;
ALTER TABLE actor_memory
    ADD CONSTRAINT actor_memory_value_format_known
    CHECK (value_format IN (0, 1));
COMMENT ON COLUMN actor_memory.value_format IS
    'AES-GCM AAD version for value_enc. 0=legacy no-AAD, 1=AAD-bound to actor_memory.id bytes.';
