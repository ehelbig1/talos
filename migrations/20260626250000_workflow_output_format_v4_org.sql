-- Per-org root DEKs, per-table cutover: workflow_executions.output_data_enc.
--
-- ExecutionRepository::encrypt_output now writes format v4 (per-context key
-- derived from the execution's ORG root DEK — the execution tenant is the
-- workflow's org, carried on workflow_executions.org_id). Org-less rows stay v3
-- global. Widen the format CHECK to admit 4. v0/v1/v3 rows keep decrypting
-- unchanged (both decrypt sites route through decrypt_versioned, which handles
-- v4). Existing rows migrate lazily on the next output write.

ALTER TABLE workflow_executions
    DROP CONSTRAINT IF EXISTS workflow_executions_output_data_format_known;
ALTER TABLE workflow_executions
    ADD CONSTRAINT workflow_executions_output_data_format_known
    CHECK (output_data_format IN (0, 1, 3, 4));

COMMENT ON COLUMN workflow_executions.output_data_format IS
    'AES-GCM AAD version for output_data_enc. 0=legacy no-AAD, 1=AAD-bound to '
    'execution id, 3=AAD-bound + per-context-derived key (global DEK), 4=same but '
    'derived from the execution''s per-ORG root DEK. See '
    'talos_secrets_manager::AAD_FORMAT_V4_ORG_DERIVED.';
