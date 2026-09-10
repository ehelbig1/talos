-- The WASM cache sweep evicts BYTES, not ROWS — and `last_used_at` becomes live.
--
-- Background (2026-09-10 whole-codebase review, "WASM-cache retention knob is
-- dead"). `ModuleRegistry::enforce_cache_limits` ran `DELETE FROM modules` when
-- `WASM_CACHE_MAX_MODULES` / `WASM_CACHE_MAX_SIZE_MB` were exceeded, and nothing
-- in its predicate asked whether a workflow, webhook or watch channel still
-- referenced the module. `module_executions.module_id` is ON DELETE CASCADE, so
-- the module's whole execution history and its `module_execution_logs` went
-- with the row; `workflow_nodes.module_id` was SET NULL; `source_code` was
-- lost outright. At 13–18 MB per JS/Python component the 500 MB default cap is
-- ~30 user modules. Separately, `cleanup_old_modules` deleted rows whose
-- `last_used_at` was older than `WASM_CACHE_RETENTION_DAYS`, and the ONLY
-- writer of `modules.last_used_at` (`increment_usage`) had zero callers, so
-- every row read `last_used_at IS NULL` and the knob was inert.
--
-- This migration is the schema half of the fix:
--
--   1. `modules.wasm_evicted_at` (nullable). The sweep now runs
--      `UPDATE modules SET wasm_bytes = NULL, wasm_evicted_at = NOW()` on an
--      evictable row and keeps everything else — the row, `source_code`, the
--      FK children, the execution history. A reader that finds
--      `wasm_bytes IS NULL AND wasm_evicted_at IS NOT NULL` reports "bytes
--      evicted; recompile with hot_update_module" instead of "not found".
--
--   2. A BEFORE UPDATE trigger that clears `wasm_evicted_at` whenever a write
--      lands non-NULL `wasm_bytes`. There are five `SET wasm_bytes = …` /
--      upsert writers across four crates (talos-registry, talos-module-repository,
--      talos-workflow-repository, talos-advanced-repository); a trigger is the
--      one place that covers all of them AND any future one, so a recompile can
--      never leave a stale "evicted" marker beside live bytes.
--
--   3. ONE-TIME DERIVATION of `last_used_at` from `module_executions`. The
--      registry now stamps `last_used_at` on the dispatch-side read (throttled
--      to at most one write per module per hour), but without a backfill every
--      existing module would present as idle-forever the moment the retention
--      knob started working and be byte-evicted on the first sweep. MAX(started_at)
--      is exactly the recency the sweep already derived at eviction time (its
--      LATERAL `last_exec`), so this writes nothing the sweep did not already
--      believe. Rows with no execution history stay NULL and fall back to
--      `created_at` in the sweep's ordering, as before. This block runs once,
--      touches only NULL cells, and is NOT re-run by the application.
--
--   4. `wasm_evicted_at` joins the `modules` updated_at MAINTENANCE-column
--      declaration (migration 20260905120000): an eviction is not an edit of
--      the module, exactly as a recompile is not.
--
-- Idempotent throughout (`IF NOT EXISTS` / `IF EXISTS` / `OR REPLACE`).

ALTER TABLE modules ADD COLUMN IF NOT EXISTS wasm_evicted_at timestamptz;

COMMENT ON COLUMN modules.wasm_evicted_at IS
  'Set by the WASM cache sweep when it NULLs wasm_bytes on an idle, unreferenced '
  'module (row, source_code and execution history are kept). Cleared by trigger '
  'whenever a write lands non-NULL wasm_bytes. NULL bytes + NULL here = never compiled.';

COMMENT ON COLUMN modules.last_used_at IS
  'Dispatch-side recency stamp, written by ModuleRegistry::touch_last_used at most '
  'once per module per hour (one-time backfill from module_executions on 2026-09-10). '
  'The WASM cache sweep reads GREATEST(last_used_at, latest module_executions.started_at).';

COMMENT ON COLUMN modules.usage_count IS
  'Incremented by the same throttled dispatch-side touch as last_used_at, so it counts '
  'hours-with-at-least-one-dispatch, not dispatches. module_executions holds the count.';

-- ---------------------------------------------------------------------------
-- 2. A recompile clears the eviction marker, whichever writer performed it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION modules_clear_wasm_evicted_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.wasm_evicted_at := NULL;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS modules_clear_wasm_evicted_at ON modules;
-- Named to sort BEFORE `modules_set_updated_at` (triggers fire in name order),
-- so the shared updated_at verdict sees the already-cleared marker — and since
-- both `wasm_bytes` and `wasm_evicted_at` are declared maintenance columns
-- below, a bytes-only recompile still does not bump `updated_at`.
CREATE TRIGGER modules_clear_wasm_evicted_at
    BEFORE UPDATE OF wasm_bytes ON modules
    FOR EACH ROW
    WHEN (NEW.wasm_bytes IS NOT NULL AND NEW.wasm_evicted_at IS NOT NULL)
    EXECUTE FUNCTION modules_clear_wasm_evicted_at();

-- ---------------------------------------------------------------------------
-- 3. One-time backfill of last_used_at from the execution history.
-- ---------------------------------------------------------------------------
UPDATE modules
   SET last_used_at = sub.max_started
  FROM (SELECT module_id, MAX(started_at) AS max_started
          FROM module_executions
         GROUP BY module_id) AS sub
 WHERE modules.id = sub.module_id
   AND modules.last_used_at IS NULL;

-- ---------------------------------------------------------------------------
-- 4. Re-declare the `modules` updated_at maintenance columns with the new one.
--    Same shape and the same existence guard as 20260905120000: a declaration
--    naming a column that does not exist would silently disable the guard, so
--    it REFUSES instead.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    maintenance_columns text[] := ARRAY[
        'wasm_bytes','content_hash','size_bytes','compiled_at',
        'usage_count','last_used_at','wasm_evicted_at'
    ];
    missing text[];
    arg_list text;
BEGIN
    IF to_regclass('public.modules') IS NULL THEN
        RAISE NOTICE 'updated_at: table modules absent, skipping';
        RETURN;
    END IF;

    SELECT array_agg(c)
      INTO missing
      FROM unnest(maintenance_columns) AS c
     WHERE NOT EXISTS (
         SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'modules'
            AND column_name = c
     );

    IF missing IS NOT NULL THEN
        RAISE EXCEPTION
            'updated_at maintenance declaration for "modules" names column(s) % that do not exist. '
            'Fix the declaration — a name that matches nothing silently disables the guard.',
            missing;
    END IF;

    SELECT COALESCE(string_agg(quote_literal(c), ', '), '')
      INTO arg_list
      FROM unnest(maintenance_columns) AS c;

    EXECUTE 'DROP TRIGGER IF EXISTS modules_set_updated_at ON public.modules';
    EXECUTE format(
        'CREATE TRIGGER modules_set_updated_at BEFORE UPDATE ON public.modules '
        'FOR EACH ROW EXECUTE FUNCTION update_updated_at_column(%s)',
        arg_list);
END $$;
