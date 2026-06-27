-- Per-org root DEKs, per-table cutover: module_executions payload columns.
--
-- encrypt_payload_bundle now writes format v4 (per-context key derived from the
-- execution's ORG root DEK — the execution tenant is the workflow's org) for
-- workflow-bound module executions; standalone / org-less rows stay v3 under the
-- global DEK. Widen the format CHECK to admit 4. v0/v1/v2/v3 rows keep decrypting
-- unchanged (decrypt_payload_slot routes through decrypt_versioned, which handles
-- v4; the per-slot AAD is identical for v2/v3/v4). Existing rows migrate lazily on
-- the next write or via the backfill example.

ALTER TABLE module_executions
    DROP CONSTRAINT IF EXISTS module_executions_payload_format_known;
ALTER TABLE module_executions
    ADD CONSTRAINT module_executions_payload_format_known
    CHECK (payload_format IN (0, 1, 2, 3, 4));

COMMENT ON COLUMN module_executions.payload_format IS
    'AES-GCM AAD version for input/output/trigger_metadata_enc. 0=legacy no-AAD, '
    '1=AAD-bound to execution id, 2=+per-slot tag, 3=+per-context-derived key '
    '(global DEK), 4=same but derived from the execution''s per-ORG root DEK. See '
    'talos_secrets_manager::AAD_FORMAT_V4_ORG_DERIVED.';
