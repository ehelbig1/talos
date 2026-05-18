-- Phase A of `module_executions` payload encryption (additive).
--
-- Module executions can carry sensitive payloads (LLM responses, scraped
-- data, OAuth-fetched user content, secrets-resolved HTTP bodies). The
-- existing DLP redaction catches known patterns (sk-*, ghp_*, Bearer,
-- email regex) but novel formats slip through. Envelope encryption
-- closes that gap.
--
-- Phase A — additive: writers transparently encrypt when SecretsManager
-- is available; readers prefer ciphertext, fall back to plaintext for
-- legacy rows. Phase B (terminal: drop plaintext columns, NOT NULL on
-- ciphertext columns) is deferred — same shape as the actor_memory
-- Phase A→B sequence.
--
-- Wire format mirrors `actor_memory.value_enc`: opaque BYTEA produced
-- by `SecretsManager.encrypt_value`, decrypted via
-- `SecretsManager.decrypt_value_by_key(payload_enc_key_id, bytes)`.
-- All three payload columns (input_data, output_data, trigger_metadata)
-- share a single `payload_enc_key_id` because they're written together
-- via the same DEK.

ALTER TABLE module_executions
    ADD COLUMN input_data_enc        BYTEA,
    ADD COLUMN output_data_enc       BYTEA,
    ADD COLUMN trigger_metadata_enc  BYTEA,
    ADD COLUMN payload_enc_key_id    UUID REFERENCES encryption_keys(id) ON DELETE RESTRICT;

-- Partial index over rows that still need encryption — `input_data` is
-- the leading indicator since it's written at create time. Phase B will
-- drop this index along with the legacy columns.
CREATE INDEX idx_module_executions_needs_payload_encryption
    ON module_executions(id)
    WHERE payload_enc_key_id IS NULL
      AND (input_data IS NOT NULL OR output_data IS NOT NULL OR trigger_metadata IS NOT NULL);

COMMENT ON COLUMN module_executions.input_data_enc IS
    'AES-256-GCM ciphertext of input_data JSON. NULL during the Phase A → Phase B window for legacy rows whose plaintext still lives in input_data.';
COMMENT ON COLUMN module_executions.output_data_enc IS
    'AES-256-GCM ciphertext of output_data JSON. NULL during Phase A→B window for legacy rows.';
COMMENT ON COLUMN module_executions.trigger_metadata_enc IS
    'AES-256-GCM ciphertext of trigger_metadata JSON. NULL during Phase A→B window for legacy rows.';
COMMENT ON COLUMN module_executions.payload_enc_key_id IS
    'Shared DEK id for input_data_enc + output_data_enc + trigger_metadata_enc. Set together with the ciphertext columns in the same write. NOT NULL after Phase B.';
