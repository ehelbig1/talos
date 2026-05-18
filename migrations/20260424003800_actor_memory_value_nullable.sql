-- Phase A.1 of `actor_memory` at-rest encryption: drop NOT NULL on `value`.
--
-- The Phase A migration (20260423235406) added `value_enc` + `value_key_id`
-- but left `value NOT NULL`. The dual-write code now writes ciphertext into
-- `value_enc` and leaves `value = NULL`, which trips the NOT NULL constraint.
-- Backfill of existing plaintext rows ALSO needs to null out `value` after
-- encrypting (otherwise the ciphertext + plaintext both live on disk —
-- defeating the purpose).
--
-- Phase B (terminal) will eventually `DROP COLUMN value` entirely; this
-- migration is the bridge state.

ALTER TABLE actor_memory
    ALTER COLUMN value DROP NOT NULL;

-- Sanity check: at this point either `value` or `value_enc` must be set.
-- Skip this constraint for now — the backfill needs a window where both
-- can be NULL transiently between SELECT and UPDATE inside a tx. We'll
-- add a `CHECK ((value IS NOT NULL) OR (value_enc IS NOT NULL))` guard in
-- Phase B alongside the DROP COLUMN.
