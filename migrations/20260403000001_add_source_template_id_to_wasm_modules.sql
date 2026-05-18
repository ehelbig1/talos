-- source_template_id already exists in wasm_modules as VARCHAR(64) from migration
-- 20260309000500_add_module_template_ref.sql. We cannot re-add it as UUID (IF NOT EXISTS
-- skips the column), and we cannot alter the type here (data migration risk).
-- Instead, this migration only updates the user_modules view to surface the existing
-- varchar source_template_id alongside the uuid template_id via an explicit cast.
--
-- source_template_id stores the original template UUID for:
--   (1) provenance: list_modules shows which template each module came from
--   (2) hot_update_module: dependency lookup uses COALESCE(template_id, source_template_id::uuid)
--       so third-party crates from the original template carry through recompilation
--
-- store_module_fresh() binds module.template_id (Option<Uuid>) as a String into this
-- varchar column — PostgreSQL accepts the UUID string representation in a VARCHAR column.
CREATE OR REPLACE VIEW user_modules AS
  -- Custom sandbox compilations stored in wasm_modules
  SELECT
      m.id,
      m.name,
      m.user_id,
      COALESCE(m.capability_world, 'unknown') AS capability_world,
      m.compiled_at,
      -- source_template_id is VARCHAR(64); cast to uuid so COALESCE type matches template_id (UUID).
      -- NULL::uuid coalesces correctly; invalid strings would error but we only store valid UUIDs.
      COALESCE(m.template_id, m.source_template_id::uuid) AS template_id,
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
