-- Follow-up to 20260528120000_aead_format_version_sweep.sql (L1, 2026-05-28 review).
--
-- That migration documented actor_memory.value_format as
-- "1=AAD-bound to actor_memory.id bytes", copying the comment template used for
-- the other five tables in the sweep (which genuinely bind AAD to their own `id`
-- column). actor_memory is the odd one out: the live encrypt/decrypt paths in
-- talos-memory bind AAD via `build_memory_aad(actor_id, key)` =
-- actor_id (16 bytes) || 0x00 || key, NOT the row id. See
-- talos-memory/src/lib.rs (persist_memory / recall_semantic_filtered) and
-- build_memory_aad.
--
-- Leaving the comment as-is is a latent hazard: the column doc explicitly
-- anticipates "operator-driven re-encrypt routines lift v0 rows to v1", and a
-- routine that follows the comment and binds AAD to actor_memory.id would emit
-- ciphertext the read path can never authenticate (GCM tag mismatch ->
-- unrecoverable rows). Correct the COMMENT so any future re-encrypt routine
-- binds the AAD the read path actually expects.
--
-- Never edit an applied migration (changes the sqlx checksum); this ships the
-- correction as a new migration.

COMMENT ON COLUMN actor_memory.value_format IS
    'AES-GCM AAD version for value_enc. 0=legacy no-AAD, 1=AAD = build_memory_aad(actor_id, key) = actor_id bytes (16) || 0x00 || key (per talos_memory::build_memory_aad). NOT bound to actor_memory.id.';
