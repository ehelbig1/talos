-- Performance indexes for execution output encryption
--
-- These indexes optimize the common query patterns introduced by the
-- dual-column encryption approach (encrypted + legacy plaintext).

-- Partial index for efficiently finding rows that have encrypted output
-- (useful for monitoring encryption adoption rate)
CREATE INDEX IF NOT EXISTS idx_wf_exec_encrypted_output
    ON workflow_executions (id)
    WHERE output_data_enc IS NOT NULL;

-- Index on the encryption key foreign key for DEK rotation queries
-- ("which rows used this key?")
CREATE INDEX IF NOT EXISTS idx_wf_exec_enc_key_id
    ON workflow_executions (output_enc_key_id)
    WHERE output_enc_key_id IS NOT NULL;
