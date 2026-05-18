-- Execution output encryption at rest
--
-- Adds encrypted output storage alongside the existing plaintext JSONB column.
-- During migration window both columns coexist: new writes go to encrypted columns,
-- reads fall back to plaintext for legacy rows. A backfill step encrypts old rows,
-- after which the plaintext column can be dropped in a follow-up migration.

ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS output_data_enc BYTEA,
    ADD COLUMN IF NOT EXISTS output_enc_key_id UUID REFERENCES encryption_keys(id);

-- Index for efficiently finding un-encrypted rows during backfill
CREATE INDEX IF NOT EXISTS idx_wf_exec_unencrypted_output
    ON workflow_executions (id)
    WHERE output_data IS NOT NULL AND output_data_enc IS NULL;

COMMENT ON COLUMN workflow_executions.output_data_enc IS
    'AES-256-GCM encrypted execution output (nonce || ciphertext). Decrypted via encryption_keys.';
COMMENT ON COLUMN workflow_executions.output_enc_key_id IS
    'References the DEK used to encrypt output_data_enc. NULL for legacy plaintext rows.';
