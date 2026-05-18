-- Fix user_modules view: wasm_modules rows with template_id set are catalog-installed,
-- not sandbox-authored. The original view hardcoded 'sandbox' for ALL wasm_modules rows.
-- After r192, install_module_from_catalog writes a wasm_modules row with template_id
-- pointing at the node_templates catalog entry. That row should be labeled 'catalog'.
--
-- Updated source derivation for wasm_modules branch:
--   template_id IS NOT NULL → 'catalog'  (installed via install_module_from_catalog)
--   template_id IS NULL     → 'sandbox'  (compiled via compile_custom_sandbox)

CREATE OR REPLACE VIEW user_modules AS
  -- wasm_modules rows: catalog-installed when template_id is set, sandbox otherwise.
  SELECT
      m.id,
      m.name,
      m.user_id,
      COALESCE(m.capability_world, 'unknown') AS capability_world,
      m.compiled_at,
      m.template_id,
      m.source_code,
      CASE WHEN m.template_id IS NOT NULL THEN 'catalog'::text
           ELSE 'sandbox'::text
      END AS source
  FROM wasm_modules m
  WHERE m.user_id IS NOT NULL

  UNION ALL

  -- User-owned node_templates with compiled WASM (catalog-installed or sandbox templates)
  -- that are NOT already represented by a wasm_modules row with the same (user_id, template_id).
  -- This avoids double-counting when install_module_from_catalog writes to both tables.
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
