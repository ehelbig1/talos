-- Phase 5.2 — remediation for two post-5.0 regressions caught in review.
--
-- 1) `module_executions.module_id` FK was ON DELETE CASCADE in the
--    original schema (`012_node_executions.sql:13`, preserved through the
--    `node_executions → module_executions` rename in `015_rename_tables.sql`).
--    Phase 5 (`20260423050000_phase5_drop_legacy_tables.sql:75-77`) repointed
--    the FK to `modules(id)` but set `ON DELETE RESTRICT`, causing
--    `delete_module` / `batch_delete_modules` / `cleanup_modules` to FK-violate
--    on any module that has ever executed. Restore the original CASCADE
--    so `delete_module` succeeds and the execution trail is reaped with
--    the module — matching the pre-5.0 contract and user expectations.
--
-- 2) `idx_modules_hash ON wasm_modules(content_hash)` was dropped with the
--    legacy table in Phase 5. `registry::store_module` still runs a
--    `SELECT id FROM modules WHERE content_hash = $1 ...` dedup query on
--    every compile/install — now a seq-scan of `modules`. Add the
--    equivalent partial index on the unified table.

-- ── Step 1: restore module_executions.module_id CASCADE semantics ─────

ALTER TABLE module_executions
    DROP CONSTRAINT IF EXISTS module_executions_module_id_fkey;

ALTER TABLE module_executions
    ADD CONSTRAINT module_executions_module_id_fkey
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE;

-- ── Step 2: add content_hash dedup index ──────────────────────────────

CREATE INDEX IF NOT EXISTS modules_content_hash
    ON modules(content_hash)
    WHERE content_hash IS NOT NULL;

-- ── Step 3: refresh planner stats after Phase 4 UPDATEs + Phase 5.1 ──
-- Cheap insurance against stale stats on the tables we just rewrote.

ANALYZE modules;
ANALYZE workflows;
ANALYZE workflow_versions;
