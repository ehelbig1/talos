-- Phase 5.1 — drop the legacy alias columns on `modules`.
--
-- Phase 5 dropped `wasm_modules` + `node_templates` tables but kept
-- `modules.legacy_template_id` + `modules.legacy_wasm_module_id` for
-- one more deploy cycle so CLI callers passing a legacy UUID could
-- still resolve. The Phase 5.1 code migration (same rebuild) collapsed
-- every 3-shape id matcher in the controller to canonical-only:
--
--   Before:  WHERE (id = $1 OR legacy_template_id = $1 OR legacy_wasm_module_id = $1)
--   After:   WHERE id = $1
--
-- And simplified:
--   - `module_execution_store::resolve_module_id` → identity function
--   - `module_fetcher::load_rate_limits` 3-branch UNION → single SELECT
--   - `find_template_id_via_wasm_module` → canonical id lookup
--   - Row-parser COALESCE projections → direct id read
--
-- With no in-tree code referencing the alias columns, they're safe to
-- drop. External callers passing a pre-Phase-4 UUID will now see
-- `Module not found` / `rows_affected = 0` instead of resolving via
-- alias — the expected post-5.1 behaviour.

-- ── Step 1: rewrite the user_modules view to not depend on aliases ───
-- The old view projected `COALESCE(legacy_template_id, id) AS template_id`
-- and used `legacy_template_id IS NOT NULL AND legacy_template_id <> id`
-- as a catalog-source heuristic. Post-5.1 neither branch can fire —
-- catalog modules are already identified by `kind = 'catalog'`.

CREATE OR REPLACE VIEW user_modules AS
SELECT
    id,
    name,
    user_id,
    capability_world,
    compiled_at,
    id AS template_id,
    source_code,
    CASE
        WHEN kind = 'catalog' THEN 'catalog'
        WHEN kind = 'extracted' THEN 'extracted'
        ELSE 'sandbox'
    END AS source
FROM modules m
WHERE user_id IS NOT NULL;

-- ── Step 2: drop the alias columns + their partial indexes ───────────
-- Partial indexes drop automatically when their indexed column is
-- dropped; the explicit DROP INDEX calls are idempotent safety nets
-- in case an operator dropped the columns manually out-of-band.

DROP INDEX IF EXISTS modules_legacy_template_id;
DROP INDEX IF EXISTS modules_legacy_wasm_module_id;

ALTER TABLE modules DROP COLUMN IF EXISTS legacy_template_id;
ALTER TABLE modules DROP COLUMN IF EXISTS legacy_wasm_module_id;
