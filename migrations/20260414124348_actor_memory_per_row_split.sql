-- Re-run the actor_memory envelope split with per-row error tolerance.
--
-- The initial split in `20260414115200_actor_memory_metadata_column.sql` used
-- a single bulk UPDATE inside a DO block. PL/pgSQL's EXCEPTION handler in that
-- shape catches errors but aborts the whole UPDATE — one malformed row
-- silently prevents ALL envelope-shaped rows from migrating. This migration
-- re-processes the split with a cursor loop so a single bad row only
-- poisons itself, not the batch.
--
-- NOTE: `actor_memory.value` is `jsonb` (not TEXT), so the envelope check
-- is a direct `jsonb_typeof(value) = 'object'` against the parsed value;
-- no regex-on-text cast. The earlier migration's `value ~ '^\s*\{'` was
-- incorrect under the actual schema and is why it no-op'd.
--
-- Safe to run against a DB where the earlier migration already did partial
-- work: `metadata IS NULL` filters out rows that were successfully split
-- previously, and the envelope-shape check skips rows that were never
-- envelopes in the first place.

DO $$
DECLARE
    r RECORD;
    new_value JSONB;
    new_metadata JSONB;
    split_count INT := 0;
    skipped_count INT := 0;
BEGIN
    FOR r IN
        SELECT id, value
        FROM actor_memory
        WHERE metadata IS NULL
          AND jsonb_typeof(value) = 'object'
          AND value ? 'value'
          AND value ? 'metadata'
    LOOP
        BEGIN
            -- Preserve the inner payload's JSON type exactly — strings stay
            -- strings, objects stay objects. Don't text-stringify objects,
            -- which would change the bytes round-tripped by `get`.
            new_value := r.value->'value';
            new_metadata := r.value->'metadata';

            UPDATE actor_memory
            SET value = new_value,
                metadata = new_metadata
            WHERE id = r.id;

            split_count := split_count + 1;
        EXCEPTION WHEN others THEN
            -- Single bad row; log and continue. Nested BEGIN/EXCEPTION
            -- creates an implicit SAVEPOINT, so this rolls back only the
            -- current iteration — the outer migration transaction (and
            -- other rows) remain intact.
            skipped_count := skipped_count + 1;
            RAISE NOTICE 'actor_memory per-row split skipped row % (%): %',
                r.id, SQLSTATE, SQLERRM;
        END;
    END LOOP;

    RAISE NOTICE 'actor_memory per-row split complete: % rows migrated, % rows skipped',
        split_count, skipped_count;
END
$$;
