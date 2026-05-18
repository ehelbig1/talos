-- Phase 3.2 prep of module entity unification (docs/module-entity-consolidation.md):
-- redirect the `user_modules` view to query the new `modules` table instead
-- of UNIONing the legacy wasm_modules + node_templates pair.
--
-- This is a single point of control — every Rust caller that queries
-- `user_modules` (handle_list_modules, list_module_catalog, system_status,
-- and any GraphQL surface that joins on it) automatically migrates without
-- code changes.
--
-- Backward compatibility: the projected column set + types stay identical.
-- Legacy id forwarding is preserved via `legacy_template_id` so workflows
-- whose graph_json references the old template id still resolve via this
-- view. The `source` column derivation maps directly from `modules.kind`:
--   modules.kind = 'catalog'   → source = 'catalog'
--   modules.kind = 'sandbox'   → source = 'sandbox'
--   modules.kind = 'extracted' → source = 'sandbox'  (extracted modules
--                                came from inline rust_code in a workflow
--                                node — same operator-mental-model as
--                                sandbox; no consumer of this view today
--                                needs to distinguish)
--
-- Idempotent: CREATE OR REPLACE VIEW.
-- Rollback: re-apply migration 20260404000002 to restore the legacy UNION.

CREATE OR REPLACE VIEW user_modules AS
  SELECT
      m.id,
      m.name,
      m.user_id,
      m.capability_world,
      m.compiled_at,
      -- Surface legacy_template_id as `template_id` so existing callers
      -- that pivot on this column (e.g. install_module_from_catalog's
      -- "show me my installed catalog templates" query) keep working
      -- unchanged. Falls back to modules.id when no legacy alias exists
      -- (newly-authored modules from after Phase 3.2 onwards).
      COALESCE(m.legacy_template_id, m.id) AS template_id,
      m.source_code,
      CASE WHEN m.kind = 'catalog' THEN 'catalog'::text
           ELSE 'sandbox'::text
      END AS source
  FROM modules m
  WHERE m.user_id IS NOT NULL;

COMMENT ON VIEW user_modules IS
  'Phase 3.2 of module entity unification: now backed by the unified `modules` table. The legacy UNION over wasm_modules + node_templates was removed once read-side cutover completed. See docs/module-entity-consolidation.md.';
