-- A caller-measured duration must survive the trigger, and every duration
-- must say which clock produced it.
--
-- ── The defect ──────────────────────────────────────────────────────────
-- The engine measures each node dispatch MONOTONICALLY
-- (`Instant::elapsed()`, i.e. CLOCK_MONOTONIC — the correct clock for "how
-- long did this take") and binds the result into `record_completed`'s
-- UPDATE.  `calculate_module_execution_duration()` then overwrote it
-- UNCONDITIONALLY with `completed_at - started_at`, a WALL-CLOCK interval.
--
-- Proven in situ, not inferred (live DB, rolled back):
--
--     UPDATE module_executions SET status='completed',
--            completed_at=NOW(), duration_ms=1234 WHERE id = <row>;
--     -- stored: 10800000   (= the 3h wall gap, not the supplied 1234)
--
-- On a host that suspends, the two clocks are not the same measurement.
-- Measured on the live stack over the 18 365 completed rows that also have
-- a monotonic counterpart in `execution_cost_rollup.wall_time_ms`:
--
--     mean wall 10 617 ms   vs   mean monotonic 1 203 ms   (8.8x)
--     max  wall  7 335 687 ms (2h 2m)  vs  max monotonic 277 040 ms (4m 37s)
--
-- and per-row, the worst offenders are pure suspend artifacts: one node
-- recorded at 5 614 097 ms consumed 105 483 ms of monotonic time — the host
-- slept for 94 of those minutes.  A `duration_ms` like that is not a
-- duration; it is the length of a nap.
--
-- ── What this migration does NOT do ─────────────────────────────────────
-- It does not drop or disable the trigger.  Twelve writers close a
-- `module_executions` row WITHOUT supplying a duration and depend on the
-- trigger to derive one: `ModuleExecutionService`'s
-- complete/fail/timeout/complete_from_worker/fail_from_worker/
-- cleanup_stuck_executions, and the six sibling-cancellation sites
-- (workflow + advanced repositories, node_hook, workflow_chains, scheduler
-- x2) plus the `cancel_siblings_on_workflow_fail` DB trigger.  For all of
-- them wall clock is the ONLY measurement that exists — no monotonic clock
-- spans "row opened by process A, closed by the sweep in process B" — so
-- the derivation stays, and stays correct, for them.
--
-- The trigger simply stops overwriting a value the caller measured.
--
-- ── Provenance, because the column is irreducibly mixed ─────────────────
-- After this change `module_executions.duration_ms` legitimately holds two
-- different measurements: monotonic where the engine measured the dispatch,
-- wall clock where the sweep/cancel paths could only subtract timestamps.
-- A cutover instant cannot separate those — both keep arriving after the
-- cutover.  So the row says which clock it used:
--
--   'monotonic'  the writer measured with CLOCK_MONOTONIC.  Trustworthy as
--                a duration; immune to host suspend.
--   'wallclock'  derived here as `completed_at - started_at`.  Correct on a
--                host that never sleeps, an over-count by exactly the sleep
--                otherwise.
--   NULL         unknown.  Every row written before this migration, and any
--                row whose `duration_ms` is NULL.
--
-- Existing rows are deliberately NOT rewritten and NOT relabelled: their
-- stored numbers were computed by the old trigger and remain wall clock.
-- A backfill could only stamp 'wallclock' onto values that are already
-- suspect, at the cost of touching every row's `updated_at` (the sibling
-- BEFORE UPDATE trigger) — it would buy accuracy nowhere.  NULL means
-- "written before the split", which is the honest label for them.
--
-- NOT changed here: `compute_execution_event_duration()` on
-- `execution_events`.  It derives from two event timestamps because nothing
-- supplies a duration to that INSERT (all three writers —
-- `talos-engine::event_sink`, `talos-execution-orchestration::terminal_event`,
-- `ExecutionRepository::insert_execution_event` — name their columns
-- explicitly and none names `duration_ms`).  It discards nothing, its column
-- comment already says "wall-clock", and its meaning is uniform.  Giving it
-- a caller-wins guard with no provenance marker would manufacture the mixed
-- column this migration exists to label.

ALTER TABLE module_executions
    ADD COLUMN IF NOT EXISTS duration_source TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'module_executions_duration_source_check'
          AND conrelid = 'module_executions'::regclass
    ) THEN
        ALTER TABLE module_executions
            ADD CONSTRAINT module_executions_duration_source_check
            CHECK (duration_source IN ('monotonic', 'wallclock'));
    END IF;
END $$;

-- Caller-wins.  `NEW.duration_ms IS NULL` is exactly "the caller supplied
-- nothing" here, not merely a proxy for it: on the transition this trigger
-- guards (`OLD.completed_at IS NULL`) the row has never been finalized, and
-- no writer in the workspace sets `duration_ms` without also setting
-- `completed_at` — so `OLD.duration_ms` is always NULL at this point, and an
-- UPDATE that omits the column leaves `NEW.duration_ms` NULL too.
CREATE OR REPLACE FUNCTION calculate_module_execution_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
        IF NEW.duration_ms IS NULL THEN
            -- CLAMPED. `duration_ms` is `integer`, so the largest value it
            -- can hold is 2147483647 ms = 24.8 days. The unguarded form
            -- raised `integer out of range` INSIDE this trigger and FAILED
            -- THE WHOLE UPDATE for any row open longer than that — and the
            -- writers that depend on this derivation are precisely the ones
            -- that touch such rows (`cleanup_stuck_executions`, the sibling
            -- cancels, the scheduler timeout path). Measured on the live DB
            -- 2026-08-31: 7 rows open, oldest 43.3 days, ONE already past
            -- the limit — so the next sweep touching it would have errored.
            -- Clamping keeps the sweep able to close the row; the saturated
            -- value is honest for a duration nobody measured, and
            -- `duration_source = 'wallclock'` already warns readers off
            -- aggregating it.
            NEW.duration_ms := LEAST(
                EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at)) * 1000,
                2147483647::bigint
            )::int;
            NEW.duration_source := 'wallclock';
        END IF;
        -- Caller supplied a duration: leave BOTH columns exactly as bound.
        -- The writer, not this trigger, knows which clock it read; the
        -- engine's `record_completed` binds 'monotonic' alongside the value.
        -- A caller that supplies a duration but no source leaves the source
        -- NULL — unknown provenance, which is the truth about it.
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON COLUMN module_executions.duration_ms IS
    'Elapsed milliseconds for this module dispatch. READ duration_source '
    'BEFORE AGGREGATING: monotonic rows are real durations, wallclock rows '
    'over-count by any host suspend that occurred during the dispatch, and '
    'NULL-source rows (everything written before 2026-08-31) are wall clock '
    'from a period when the engine''s monotonic measurement was discarded.';

COMMENT ON COLUMN module_executions.duration_source IS
    'Which clock produced duration_ms. ''monotonic'' = CLOCK_MONOTONIC, '
    'measured by the writer across the dispatch (engine single-node, loop '
    'iteration, and pipeline-step paths); trustworthy as a duration. '
    '''wallclock'' = derived by calculate_module_execution_duration() as '
    'completed_at - started_at, the only measurement available to the '
    'stuck-execution sweep and the sibling-cancellation paths. NULL = '
    'unknown: duration_ms is NULL, or the row predates this column.';

-- Correcting a name, not a value. `execution_cost_rollup.wall_time_ms` is
-- populated from `Instant::elapsed()` in the engine's dispatch loop
-- (engine.rs `node_start_times`) and is therefore MONOTONIC despite what it
-- is called — it was, before this migration, the only trustworthy per-node
-- duration in the database, and its name says the opposite. Coverage is
-- narrower than `module_executions`: a row exists only for a SUCCESSFUL node
-- that reported non-zero fuel, so failures and zero-fuel system nodes are
-- absent.
COMMENT ON COLUMN execution_cost_rollup.wall_time_ms IS
    'MONOTONIC elapsed milliseconds (Instant::elapsed) for one node '
    'dispatch, despite the column name. Rows exist only for successful '
    'nodes that reported fuel > 0.';

-- Restating what the sibling trigger produces, so a reader comparing the two
-- columns is not left to infer it.
COMMENT ON COLUMN execution_events.duration_ms IS
    'Wall-clock milliseconds from the matching node_started event to this '
    'completion event, computed by compute_execution_event_duration(). Wall '
    'clock is the ONLY measurement available at INSERT time — no writer '
    'supplies a duration to this table — so on a suspending host these '
    'over-count by the sleep. For a suspend-immune per-node duration use '
    'module_executions.duration_ms WHERE duration_source = ''monotonic''.';
