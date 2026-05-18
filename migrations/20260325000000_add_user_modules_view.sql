-- user_modules: single source of truth for all user-owned compiled modules.
--
-- Before this view, tools queried either wasm_modules (for custom sandbox
-- compilations) or node_templates (for catalog-installed modules) depending
-- on which engineer wrote them, causing count disagreements between
-- get_system_status, list_modules, and list_module_catalog.
--
-- The view unions both tables with a consistent schema so every tool
-- can query a single source of truth and eliminate that class of bugs.
--
-- source values:
--   'sandbox' — compiled via compile_custom_sandbox (wasm_modules) or
--               stored as a user-owned sandbox template (node_templates
--               with category = 'sandbox')
--   'catalog' — installed via install_module_from_catalog (node_templates
--               with user_id set and category != 'sandbox')

CREATE OR REPLACE VIEW user_modules AS
  -- Custom sandbox compilations stored in wasm_modules
  SELECT
      m.id,
      m.name,
      m.user_id,
      COALESCE(m.capability_world, 'unknown') AS capability_world,
      m.compiled_at,
      m.template_id,
      m.source_code,
      'sandbox'::text AS source
  FROM wasm_modules m
  WHERE m.user_id IS NOT NULL

  UNION ALL

  -- User-owned node_templates with compiled WASM (catalog-installed or
  -- sandbox templates) that are NOT already represented by a wasm_modules
  -- row (avoids double-counting when compile_custom_sandbox creates both).
  SELECT
      t.id,
      t.name,
      t.user_id,
      COALESCE(t.capability_world, 'unknown') AS capability_world,
      t.created_at AS compiled_at,
      t.id          AS template_id,
      t.code_template AS source_code,
      CASE WHEN t.category = 'sandbox' THEN 'sandbox'::text
           ELSE 'catalog'::text
      END AS source
  FROM node_templates t
  WHERE t.user_id IS NOT NULL
    AND t.precompiled_wasm IS NOT NULL
    AND NOT EXISTS (
        SELECT 1
        FROM wasm_modules m
        WHERE m.template_id = t.id
          AND m.user_id = t.user_id
    );
