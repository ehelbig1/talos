-- Per-org root DEKs, per-table cutover: webhook_triggers.signing_secret_enc.
--
-- talos-api create_webhook_trigger now writes format v4 (per-context key derived
-- from the owner's PERSONAL-org root DEK) instead of v3 (global DEK). AAD stays
-- bound to trigger_id. Widen the format CHECK to admit 4. v0/v1/v3 rows keep
-- decrypting unchanged (decrypt_versioned routes v4 through the v3 derived path);
-- they migrate lazily on the next signing-secret update / re-create.

ALTER TABLE webhook_triggers
    DROP CONSTRAINT IF EXISTS webhook_triggers_signing_secret_format_known;
ALTER TABLE webhook_triggers
    ADD CONSTRAINT webhook_triggers_signing_secret_format_known
    CHECK (signing_secret_format IN (0, 1, 3, 4));

COMMENT ON COLUMN webhook_triggers.signing_secret_format IS
    'AES-GCM AAD version for signing_secret_enc. 0=legacy no-AAD, 1=AAD-bound to '
    'trigger_id, 3=AAD-bound + per-context-derived key (global DEK), 4=same but '
    'derived from the owner''s per-ORG root DEK. See '
    'talos_secrets_manager::AAD_FORMAT_V4_ORG_DERIVED.';
