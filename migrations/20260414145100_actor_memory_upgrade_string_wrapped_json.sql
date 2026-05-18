-- Upgrade legacy Value::String-wrapped JSON in `actor_memory.value` to proper JSON.
--
-- Background: entries written before the envelope fix (2026-04-14) went through
-- a worker `store_with_embedding` path that was:
--
--     let json_val = match entry.metadata {
--         Some(ref meta) => serde_json::json!({"value": entry.value, "metadata": meta}),
--         None           => serde_json::json!(entry.value),   // ← the bug
--     };
--
-- When the caller's `entry.value` was itself a JSON-encoded object (e.g.
-- `{"captured_at_ms":...}`), this produced `Value::String("{...}")` instead
-- of `Value::Object({...})`, and the DB row ended up with `jsonb_typeof =
-- 'string'` — a JSON string whose content happened to be another JSON
-- document. Round-tripping through `agent_memory::search` double-serializes
-- these (`"\"{\\\"captured_at_ms\\\":...}\""` in retrieve snippets).
--
-- Fix: detect rows whose `value` is a JSON string that successfully parses
-- as a JSON object, and replace the wrapper with the parsed object. Leave
-- rows whose content doesn't parse or isn't an object untouched — those
-- are genuinely stored strings (e.g. simple memory values).
--
-- Per-row tolerant: each iteration's nested BEGIN/EXCEPTION creates an
-- implicit SAVEPOINT so one malformed row doesn't abort the batch.
-- Idempotent: the filter (`jsonb_typeof = 'string'`) stops matching once
-- the row is upgraded, and rerunning is a no-op.

DO $$
DECLARE
    r RECORD;
    inner_text TEXT;
    inner_json JSONB;
    upgraded INT := 0;
    skipped INT := 0;
BEGIN
    FOR r IN
        SELECT id, value
        FROM actor_memory
        WHERE jsonb_typeof(value) = 'string'
    LOOP
        BEGIN
            -- Extract the raw string content from the JSON string node.
            -- `#>> '{}'` is the idiomatic way to pull the unquoted text
            -- out of a top-level JSON string in Postgres.
            inner_text := r.value #>> '{}';

            -- Cheap pre-filter: must at least *look* like a JSON object
            -- before we pay the cast cost. Also skips plain strings
            -- ("hello world") without triggering a parse failure.
            IF inner_text IS NULL OR left(ltrim(inner_text), 1) <> '{' THEN
                skipped := skipped + 1;
                CONTINUE;
            END IF;

            inner_json := inner_text::jsonb;

            -- Only upgrade when the parsed content is itself an object.
            -- A nested string ("\"still a string\"") stays as-is.
            IF jsonb_typeof(inner_json) = 'object' THEN
                UPDATE actor_memory
                SET value = inner_json
                WHERE id = r.id;
                upgraded := upgraded + 1;
            ELSE
                skipped := skipped + 1;
            END IF;
        EXCEPTION WHEN others THEN
            -- Unparseable content is fine — the row stays as it was.
            -- SAVEPOINT semantics roll back only this iteration.
            skipped := skipped + 1;
            RAISE NOTICE 'actor_memory string-wrap upgrade skipped row % (%): %',
                r.id, SQLSTATE, SQLERRM;
        END;
    END LOOP;

    RAISE NOTICE 'actor_memory string-wrap upgrade complete: % rows upgraded, % rows skipped',
        upgraded, skipped;
END
$$;
