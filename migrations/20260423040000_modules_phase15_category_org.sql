-- Phase 1.5 — schema additions to `modules` to unblock the remaining
-- legacy readers (`find_template_alternatives_*` and
-- `share_module_with_org`).
--
-- ── New columns ─────────────────────────────────────────────────────
-- `category`  TEXT — free-form catalog category label, distinct from
--                    the `kind` enum. Mirrors `node_templates.category`
--                    so trigram-similarity helpers ("alternatives to
--                    Jira X" → category=Integration) work against the
--                    unified table.
-- `org_id`    UUID — organisation ownership. Mirrors
--                    `wasm_modules.org_id` so `share_module_with_org`
--                    can scope visibility on the modules table directly.
--
-- ── Backfill ────────────────────────────────────────────────────────
-- For each modules row, copy the category from the matched
-- node_templates row (resolved by legacy_template_id). For sandbox /
-- extracted modules without a node_templates source, leave NULL — the
-- `kind` column already carries that signal.
--
-- For org_id, copy from the wasm_modules row (matched by
-- legacy_wasm_module_id). At time of writing every row is NULL so the
-- backfill is a no-op, but the structural copy keeps the table schema
-- aligned for the day org-scoped sharing actually carries data.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS + UPDATE WHERE column IS NULL.

ALTER TABLE modules
    ADD COLUMN IF NOT EXISTS category TEXT,
    ADD COLUMN IF NOT EXISTS org_id   UUID;

-- Hot-path indexes for the new columns. category is queried by
-- trigram similarity in `find_template_alternatives_*` so a btree
-- works for category equality but the heavy lookups also need a
-- pg_trgm GIN index. We only add the btree here — the trgm GIN
-- piggybacks on the existing `node_templates_category_trgm` until
-- find_template_alternatives_* is migrated; a follow-up migration
-- adds the GIN on `modules.category` once that work lands.
CREATE INDEX IF NOT EXISTS modules_category
    ON modules (category)
    WHERE category IS NOT NULL;

CREATE INDEX IF NOT EXISTS modules_org_id
    ON modules (org_id)
    WHERE org_id IS NOT NULL;

-- ── Backfill from node_templates.category ───────────────────────────
-- Only fills rows that were backfilled FROM a node_templates row in
-- Phase 1.1 (i.e. legacy_template_id IS NOT NULL). Per-row exception
-- handling so a single rotten template doesn't abort the migration.
DO $$
DECLARE
    r RECORD;
    updated INT := 0;
    failed INT := 0;
BEGIN
    FOR r IN
        SELECT m.id AS module_id, nt.category
        FROM modules m
        JOIN node_templates nt ON nt.id = m.legacy_template_id
        WHERE m.category IS NULL
          AND nt.category IS NOT NULL
    LOOP
        BEGIN
            UPDATE modules SET category = r.category WHERE id = r.module_id;
            updated := updated + 1;
        EXCEPTION WHEN OTHERS THEN
            failed := failed + 1;
            RAISE WARNING 'Phase 1.5 category backfill failed for module %: % (SQLSTATE %)',
                          r.module_id, SQLERRM, SQLSTATE;
        END;
    END LOOP;
    RAISE NOTICE 'Phase 1.5 category backfill: updated=%, failed=%', updated, failed;
END
$$ LANGUAGE plpgsql;

-- ── Backfill from wasm_modules.org_id ───────────────────────────────
DO $$
DECLARE
    r RECORD;
    updated INT := 0;
    failed INT := 0;
BEGIN
    FOR r IN
        SELECT m.id AS module_id, wm.org_id
        FROM modules m
        JOIN wasm_modules wm ON wm.id = m.legacy_wasm_module_id
        WHERE m.org_id IS NULL
          AND wm.org_id IS NOT NULL
    LOOP
        BEGIN
            UPDATE modules SET org_id = r.org_id WHERE id = r.module_id;
            updated := updated + 1;
        EXCEPTION WHEN OTHERS THEN
            failed := failed + 1;
            RAISE WARNING 'Phase 1.5 org_id backfill failed for module %: % (SQLSTATE %)',
                          r.module_id, SQLERRM, SQLSTATE;
        END;
    END LOOP;
    RAISE NOTICE 'Phase 1.5 org_id backfill: updated=%, failed=%', updated, failed;
END
$$ LANGUAGE plpgsql;
