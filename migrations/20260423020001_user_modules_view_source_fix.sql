-- Phase 3.2 prep follow-up: fix the `source` column derivation in the
-- redirected user_modules view (migration 20260423020000).
--
-- The previous derivation pivoted on `modules.kind` directly:
--   kind = 'catalog'   → source = 'catalog'
--   kind = 'sandbox'   → source = 'sandbox'
--   kind = 'extracted' → source = 'sandbox'
--
-- This broke the OLD view's contract that user-installed CATALOG modules
-- (created by install_module_from_catalog, which writes a per-user wasm_modules
-- row WITH template_id set) surface as source='catalog'. The Phase 1.1
-- backfill labeled those rows as kind='sandbox' because the heuristic was
-- "user_id IS NOT NULL on the joined node_template → sandbox", which the
-- catalog install pattern (per-user node_template clone) triggers.
--
-- Restore the original semantic by also treating "user-owned + has a
-- legacy_template_id forwarding alias" as a catalog install. New code paths
-- (post-Phase-3.2) that write directly to modules without legacy_template_id
-- will use the kind field as source-of-truth.

CREATE OR REPLACE VIEW user_modules AS
  SELECT
      m.id,
      m.name,
      m.user_id,
      m.capability_world,
      m.compiled_at,
      COALESCE(m.legacy_template_id, m.id) AS template_id,
      m.source_code,
      CASE
          WHEN m.kind = 'catalog' THEN 'catalog'::text
          -- User-installed catalog modules: kind was mislabeled as 'sandbox'
          -- by the Phase 1.1 backfill heuristic, but the legacy_template_id
          -- alias proves they came from install_module_from_catalog. Restore
          -- the OLD view's source='catalog' semantic for this case.
          WHEN m.kind = 'sandbox' AND m.legacy_template_id IS NOT NULL
               AND m.legacy_template_id != m.id THEN 'catalog'::text
          ELSE 'sandbox'::text
      END AS source
  FROM modules m
  WHERE m.user_id IS NOT NULL;

COMMENT ON VIEW user_modules IS
  'Phase 3.2 of module entity unification: backed by the unified `modules` table. The source column distinguishes user-installed catalog modules (legacy_template_id set, points elsewhere) from user-authored sandboxes. See docs/module-entity-consolidation.md.';
