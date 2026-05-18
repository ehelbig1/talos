-- Split agent_memory metadata out of the `value` column into a dedicated
-- `metadata` JSONB column.
--
-- Before: worker's `store_with_embedding` packed `{value, metadata}` into the
-- `value` TEXT column as JSON. The WIT `get(key) -> string` contract was thus
-- silently broken: callers expecting the raw string they stored received an
-- envelope object when metadata had been provided, and the raw string when not.
--
-- After: `metadata` lives in its own JSONB column. `value` holds exactly what
-- the caller passed. `get` returns the raw value as documented.
--
-- Legacy rows written under the envelope scheme are split opportunistically:
-- rows whose `value` parses as a JSON object containing both `value` and
-- `metadata` keys are unpacked. Rows that don't match the envelope shape are
-- left alone (worst case: caller sees the raw string they stored, which is
-- already the intended contract).

ALTER TABLE actor_memory
    ADD COLUMN IF NOT EXISTS metadata JSONB;

-- Split legacy envelope-shaped rows. Guard each step so non-JSON values
-- (which are valid under the new contract) are skipped cleanly.
DO $$
BEGIN
    UPDATE actor_memory AS m
    SET
        metadata = parsed.obj->'metadata',
        value = CASE
            WHEN jsonb_typeof(parsed.obj->'value') = 'string'
                THEN parsed.obj->>'value'
            ELSE (parsed.obj->'value')::text
        END
    FROM (
        SELECT id, value::jsonb AS obj
        FROM actor_memory
        WHERE value ~ '^\s*\{'
          AND metadata IS NULL
    ) AS parsed
    WHERE m.id = parsed.id
      AND jsonb_typeof(parsed.obj) = 'object'
      AND parsed.obj ? 'value'
      AND parsed.obj ? 'metadata';
EXCEPTION WHEN others THEN
    -- Malformed legacy row; leave untouched and let application-layer
    -- reads see the raw string (safe fallback under the new contract).
    RAISE NOTICE 'actor_memory metadata split skipped a row: %', SQLERRM;
END
$$;
