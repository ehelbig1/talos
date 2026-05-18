-- Phase 1.4 of module entity unification (docs/module-entity-consolidation.md):
-- add the columns we deferred from Phase 1.1. Without these, a Phase 3
-- cutover (drop wasm_modules / node_templates) would lose:
--   - max_memory_mb           — per-module RAM ceiling honored by the worker
--                               resource limiter
--   - imported_interfaces     — WIT interfaces the binary imports; informational
--                               (used by capability inspection / get_module_info)
--   - dependencies            — JSONB of crate name → version; used by
--                               hot_update_module to re-inject crates at recompile
--   - config                  — JSONB of per-instance config (rarely set on
--                               wasm_modules; included for completeness)
--
-- All four are nullable / have safe defaults so the column add itself is a
-- no-op for existing rows. The data backfill (this migration's UPDATE) walks
-- existing modules rows and pulls each value from the matching legacy row.
-- Idempotent: re-runs are no-ops because we only UPDATE rows where the new
-- column is still NULL.

ALTER TABLE modules
    ADD COLUMN IF NOT EXISTS max_memory_mb       INTEGER NOT NULL DEFAULT 128,
    ADD COLUMN IF NOT EXISTS imported_interfaces TEXT[]  NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS dependencies        JSONB,
    ADD COLUMN IF NOT EXISTS config              JSONB;

-- Backfill from wasm_modules siblings via legacy_wasm_module_id.
-- Single UPDATE per column to keep transaction lock time bounded.
-- Predicate `IS NULL` makes this idempotent on re-run.
UPDATE modules m
SET max_memory_mb = w.max_memory_mb
FROM wasm_modules w
WHERE m.legacy_wasm_module_id = w.id
  AND w.max_memory_mb IS NOT NULL
  AND m.max_memory_mb = 128;  -- only override the default; preserve operator-set values

UPDATE modules m
SET imported_interfaces = w.imported_interfaces
FROM wasm_modules w
WHERE m.legacy_wasm_module_id = w.id
  AND array_length(w.imported_interfaces, 1) > 0
  AND array_length(m.imported_interfaces, 1) IS NULL;  -- only fill empty rows

UPDATE modules m
SET dependencies = COALESCE(w.dependencies, t.dependencies)
FROM wasm_modules w
LEFT JOIN node_templates t ON t.id = w.template_id
WHERE m.legacy_wasm_module_id = w.id
  AND m.dependencies IS NULL
  AND COALESCE(w.dependencies, t.dependencies) IS NOT NULL;

UPDATE modules m
SET config = w.config
FROM wasm_modules w
WHERE m.legacy_wasm_module_id = w.id
  AND m.config IS NULL
  AND w.config IS NOT NULL;

-- For modules whose only source row was node_templates (catalog entries
-- without a wasm_modules sibling), pull dependencies from there too.
UPDATE modules m
SET dependencies = t.dependencies
FROM node_templates t
WHERE m.legacy_template_id = t.id
  AND m.legacy_wasm_module_id IS NULL
  AND m.dependencies IS NULL
  AND t.dependencies IS NOT NULL;

COMMENT ON COLUMN modules.max_memory_mb IS
    'Per-module RAM ceiling (MB) honored by worker resource limiter. Default 128.';
COMMENT ON COLUMN modules.imported_interfaces IS
    'WIT interfaces this binary imports. Informational; surfaced in get_module_info.';
COMMENT ON COLUMN modules.dependencies IS
    'JSONB of crate-name → version. Used by hot_update_module to re-inject crates at recompile time.';
COMMENT ON COLUMN modules.config IS
    'JSONB of per-instance config (rarely set on wasm_modules — included for completeness so Phase 3 cutover preserves the field).';
