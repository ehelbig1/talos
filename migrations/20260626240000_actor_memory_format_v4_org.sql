-- Per-org root DEKs, per-table cutover: actor_memory.value_enc.
--
-- talos-memory now writes format v4 (per-context key derived from the ACTOR's
-- org root DEK) and stamps actor_memory.org_id = the actor's org. Widen the
-- format CHECK to admit 4. v0/v1/v3 rows keep decrypting unchanged (the memory
-- crypto hook's decrypt delegates to decrypt_versioned, which handles v4).
-- Existing rows migrate lazily on the next write; clone_memories now also
-- re-encrypts v1/v3/v4 rows under the target actor's org (and no longer drops
-- v3 rows — the old clone matched only value_format = 1).

ALTER TABLE actor_memory
    DROP CONSTRAINT IF EXISTS actor_memory_value_format_known;
ALTER TABLE actor_memory
    ADD CONSTRAINT actor_memory_value_format_known
    CHECK (value_format IN (0, 1, 3, 4));

COMMENT ON COLUMN actor_memory.value_format IS
    'AES-GCM AAD version for value_enc. 0=legacy no-AAD, 1=AAD-bound to '
    '(actor_id||key), 3=AAD-bound + per-context-derived key (global DEK), 4=same '
    'but derived from the actor''s per-ORG root DEK (org_id IS NOT NULL). See '
    'talos_secrets_manager::AAD_FORMAT_V4_ORG_DERIVED.';
