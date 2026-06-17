-- Finding #1 (AEAD nonce-reuse under shared keys): introduce AAD format
-- version 3 = AAD-bound (same as v1) AND per-context key-derived. In v3
-- the AES-256-GCM key is an HKDF-SHA256 subkey of the DEK, keyed on the
-- row's AAD context (secret_id / actor_id‖key / execution_id / per-slot
-- tag), so the random-96-bit-nonce birthday budget (~2^32 messages per
-- key, NIST SP 800-38D) is consumed PER CONTEXT (≈1 message) instead of
-- globally across every row sharing the single active DEK. See
-- talos_secrets_manager::AAD_FORMAT_V3_DERIVED.
--
-- This migration only widens the encryption-format CHECK constraints so
-- the new v3 writes are accepted. There is NO data backfill: existing
-- v0/v1/v2 rows keep decrypting under their stored format (the readers
-- dispatch on the per-row format column), and rows lazily upgrade to v3
-- as they are next written (or via the operator re-encrypt routine).
--
-- Per the migration rules (never edit an applied migration) we DROP +
-- re-ADD each CHECK rather than altering the originals
-- (20260506100000_secrets_aad_format_version.sql and
-- 20260528120000_aead_format_version_sweep.sql). Every existing row is
-- 0/1/2, all within the widened sets, so the synchronous constraint
-- validation on ADD passes.

-- ── secrets.encryption_format_version ────────────────────────────────
-- Reader dispatch (decrypt_secret_record): {0,1,3}. Never 2.
ALTER TABLE secrets
    DROP CONSTRAINT IF EXISTS secrets_encryption_format_version_known;
ALTER TABLE secrets
    ADD CONSTRAINT secrets_encryption_format_version_known
    CHECK (encryption_format_version IN (0, 1, 3));

-- ── users.totp_secret_format ─────────────────────────────────────────
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_totp_secret_format_known;
ALTER TABLE users
    ADD CONSTRAINT users_totp_secret_format_known
    CHECK (totp_secret_format IN (0, 1, 3));
COMMENT ON COLUMN users.totp_secret_format IS
    'AES-GCM AAD version for totp_secret. 0=legacy no-AAD, 1=AAD-bound to users.id, 3=AAD-bound + per-context-derived key. See talos_secrets_manager::AAD_FORMAT_V3_DERIVED.';

-- ── webhook_triggers.signing_secret_format ───────────────────────────
ALTER TABLE webhook_triggers
    DROP CONSTRAINT IF EXISTS webhook_triggers_signing_secret_format_known;
ALTER TABLE webhook_triggers
    ADD CONSTRAINT webhook_triggers_signing_secret_format_known
    CHECK (signing_secret_format IN (0, 1, 3));
COMMENT ON COLUMN webhook_triggers.signing_secret_format IS
    'AES-GCM AAD version for signing_secret_enc. 0=legacy no-AAD, 1=AAD-bound to webhook_triggers.id, 3=AAD-bound + per-context-derived key.';

-- ── workflow_executions.output_data_format ───────────────────────────
ALTER TABLE workflow_executions
    DROP CONSTRAINT IF EXISTS workflow_executions_output_data_format_known;
ALTER TABLE workflow_executions
    ADD CONSTRAINT workflow_executions_output_data_format_known
    CHECK (output_data_format IN (0, 1, 3));
COMMENT ON COLUMN workflow_executions.output_data_format IS
    'AES-GCM AAD version for output_data_enc. 0=legacy no-AAD, 1=AAD-bound to workflow_executions.id, 3=AAD-bound + per-context-derived key.';

-- ── module_executions.payload_format ─────────────────────────────────
-- Writers use {0,1,2,3}: 2 = v2 per-slot AAD (input/output/trigger
-- disambiguation, talos_module_payload_encryption), 3 = v2's slot AAD
-- PLUS per-context key derivation. NOTE: the original sweep constrained
-- this column to IN (0,1) even though the v2 writer emits 2 — widening
-- to include 2 here also closes that latent gap.
ALTER TABLE module_executions
    DROP CONSTRAINT IF EXISTS module_executions_payload_format_known;
ALTER TABLE module_executions
    ADD CONSTRAINT module_executions_payload_format_known
    CHECK (payload_format IN (0, 1, 2, 3));
COMMENT ON COLUMN module_executions.payload_format IS
    'AES-GCM AAD version for {input,output,trigger_metadata}_enc. 0=legacy no-AAD, 1=row-id AAD, 2=row-id + per-slot AAD, 3=v2 AAD + per-context-derived key.';

-- ── actor_memory.value_format ────────────────────────────────────────
ALTER TABLE actor_memory
    DROP CONSTRAINT IF EXISTS actor_memory_value_format_known;
ALTER TABLE actor_memory
    ADD CONSTRAINT actor_memory_value_format_known
    CHECK (value_format IN (0, 1, 3));
COMMENT ON COLUMN actor_memory.value_format IS
    'AES-GCM AAD version for value_enc. 0=legacy no-AAD, 1=AAD-bound to (actor_id,key), 3=AAD-bound + per-context-derived key.';
