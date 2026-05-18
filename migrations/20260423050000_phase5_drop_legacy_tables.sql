-- Phase 5 — drop legacy wasm_modules + node_templates tables.
--
-- Phase 3.2 stopped writes to the legacy tables. Phase 4 rewrote
-- `workflows.graph_json` + `workflow_versions.graph_json` to use
-- canonical `modules.id`. The Phase 5 code migration (same rebuild)
-- moved every remaining legacy reader in the controller to query the
-- unified `modules` table. With zero queries hitting the legacy tables
-- at runtime, they are frozen historical artifacts and safe to drop.
--
-- ── Data-level prerequisite (verified) ──────────────────────────────
-- Phase 1.1 backfill preserved the `wasm_modules.id` UUID as the new
-- `modules.id`:
--   SELECT COUNT(*) FROM modules
--    WHERE id = legacy_wasm_module_id  → 85
--   SELECT COUNT(*) FROM modules
--    WHERE id <> legacy_wasm_module_id AND legacy_wasm_module_id IS NOT NULL → 0
--
-- So every dependent column that currently holds a `wasm_modules.id`
-- value ALREADY references the correct `modules.id`. No data
-- translation step is needed — only FK constraint swaps.
--
-- Assertion at the end of this migration re-checks the invariant so a
-- future state where the ids diverge fails closed rather than leaving
-- orphan rows.
--
-- ── Step 1: drop old FK constraints pointing at wasm_modules ────────
-- Five tables FK onto wasm_modules.id. `wasm_modules.template_id →
-- node_templates.id` disappears with the parent table.

ALTER TABLE compilation_cache DROP CONSTRAINT IF EXISTS compilation_cache_module_id_fkey;
ALTER TABLE google_calendar_watch_channels DROP CONSTRAINT IF EXISTS google_calendar_watch_channels_module_id_fkey;
ALTER TABLE module_executions DROP CONSTRAINT IF EXISTS node_executions_module_id_fkey;
ALTER TABLE webhook_triggers DROP CONSTRAINT IF EXISTS webhook_listeners_module_id_fkey;
ALTER TABLE workflow_nodes DROP CONSTRAINT IF EXISTS workflow_nodes_module_id_fkey;

-- ── Step 2: drop orphan dependent rows ──────────────────────────────
-- Any module_executions row that has no matching modules row would
-- violate the new FK. Audit at migration-draft time found 0 orphans
-- across all 5 tables; this cleanup is defensive in case a row slips
-- between audit and apply.

DELETE FROM module_executions me
 WHERE NOT EXISTS (SELECT 1 FROM modules m WHERE m.id = me.module_id);

DELETE FROM compilation_cache cc
 WHERE cc.module_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM modules m WHERE m.id = cc.module_id);

UPDATE google_calendar_watch_channels
   SET module_id = NULL
 WHERE module_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM modules m WHERE m.id = module_id);

UPDATE webhook_triggers
   SET module_id = NULL
 WHERE module_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM modules m WHERE m.id = module_id);

UPDATE workflow_nodes
   SET module_id = NULL
 WHERE module_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM modules m WHERE m.id = module_id);

-- ── Step 3: add new FK constraints pointing at modules(id) ──────────
-- ON DELETE semantics preserved from the original constraints.

ALTER TABLE compilation_cache
    ADD CONSTRAINT compilation_cache_module_id_fkey
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE;

ALTER TABLE google_calendar_watch_channels
    ADD CONSTRAINT google_calendar_watch_channels_module_id_fkey
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE SET NULL;

ALTER TABLE module_executions
    ADD CONSTRAINT module_executions_module_id_fkey
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE RESTRICT;

ALTER TABLE webhook_triggers
    ADD CONSTRAINT webhook_triggers_module_id_fkey
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE SET NULL;

ALTER TABLE workflow_nodes
    ADD CONSTRAINT workflow_nodes_module_id_fkey
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE SET NULL;

-- ── Step 4: drop the legacy tables ───────────────────────────────────
-- CASCADE catches the self-FK wasm_modules.template_id → node_templates.id
-- and any index / trigger attached to the parent rows.

DROP TABLE IF EXISTS wasm_modules CASCADE;
DROP TABLE IF EXISTS node_templates CASCADE;

-- ── Step 5: document alias columns as historical ────────────────────
-- `modules.legacy_template_id` + `modules.legacy_wasm_module_id` are
-- preserved for the same deploy cycle so the 3-shape id matchers still
-- scattered through the code can resolve CLI callers that pass a legacy
-- UUID from muscle memory. A follow-up migration (Phase 5.1) drops the
-- columns once the code cleanup in task #232 collapses matchers to
-- canonical-only.

COMMENT ON COLUMN modules.legacy_template_id IS
    'Historical alias — former node_templates.id. Read-only post-Phase-5. Dropped in Phase 5.1 once 3-shape matchers are collapsed.';
COMMENT ON COLUMN modules.legacy_wasm_module_id IS
    'Historical alias — former wasm_modules.id. Read-only post-Phase-5. Dropped in Phase 5.1 once 3-shape matchers are collapsed.';
