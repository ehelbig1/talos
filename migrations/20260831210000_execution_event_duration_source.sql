-- `execution_events.duration_ms` must stop discarding a monotonic duration
-- the engine already measured, and must say which clock produced it.
--
-- ── Why this table was correctly scoped OUT of #707, and why that changed ─
-- #707 declined to touch `compute_execution_event_duration()` on the stated
-- ground that "nothing supplies a duration to that INSERT (all three
-- writers name their columns explicitly and none names `duration_ms`)".
-- That was true, and it is still true of the writers as they stood: the
-- three INSERT sites are unchanged and none of them named the column.
--
-- What #707 did not say — because it was scoping this table out, not
-- surveying it — is that the ENGINE ALREADY HELD A MONOTONIC MEASUREMENT AT
-- TWO OF THE THREE EMIT SITES and simply never passed it down:
--
--   * `run_scheduler_loop` (engine.rs) records `std::time::Instant::now()`
--     into `node_start_times` immediately before dispatching each node and
--     reads `start.elapsed()` back when the future resolves. That value is
--     threaded into `handle_completed_future` -> `handle_node_success` /
--     `handle_node_failure` as `wall_time_ms` (a monotonic quantity despite
--     the name, exactly as #707 documented for
--     `execution_cost_rollup.wall_time_ms`), and the `node_completed` /
--     `node_failed` emit is the FIRST statement in each of those functions.
--     The value was in scope, one struct field away, and went to the hook
--     only.
--
--   * `dispatch_subworkflow` (scheduler_handlers.rs) measures
--     `dispatch_started.elapsed()` and then FORMATS IT INTO PROSE —
--     `log_message = "sub_workflow duration_ms={elapsed_ms}"` — while the
--     actual `duration_ms` column was left for the trigger to derive. A
--     measurement rendered to a string beside the column it belongs in.
--
-- So the premise "wall clock is the only value available at INSERT time"
-- held for the WRITER but not for the CALLERS of the writer. This migration
-- is the follow-up #707 named.
--
-- ── The defect, measured live rather than inferred ──────────────────────
-- The trigger derives `NEW.created_at - <matching node_started>.created_at`,
-- a WALL-CLOCK interval. On a host that suspends, that is the node's work
-- plus the nap. Over the last 7 days on this deployment, across the 2 378
-- executions whose `execution_events` node count matches their
-- `execution_cost_rollup` node count exactly (so the two populations are the
-- same nodes, not merely the same executions):
--
--     wall-clock total (execution_events.duration_ms)  24 319 076 ms
--     monotonic total  (execution_cost_rollup)          8 707 280 ms
--     inflation                                              2.79x
--     worst single execution   5 618 304 ms wall  vs  324 880 ms monotonic
--
-- The worst row, 5 614 101 ms, is the same node #707 found at 5 614 097 ms
-- in `module_executions` — the two tables recorded the same 93-minute nap
-- for a node that consumed ~105 s of monotonic time. #707 fixed one of the
-- two columns; this fixes the other.
--
-- These are USER-FACING numbers: `get_execution_trace`, `watch_execution`
-- and the GraphQL execution subscriptions all render them as node durations.
--
-- ── Caller-wins, not removal ────────────────────────────────────────────
-- The derivation stays for writers that have no measurement. There are two
-- such populations and they are not going away:
--
--   * `emit_node_lifecycle_events` (engine_dispatch_system.rs, 23 call
--     sites) emits a SYNTHETIC `node_started` + `node_completed` PAIR from
--     one spawned task AFTER the system node has already finished. Nothing
--     timed that node, and the interval the trigger derives there is the gap
--     between two adjacent INSERTs, not the duration of any work — which is
--     why all 19 zero-valued rows in the 7-day window are sub-millisecond
--     (0.307-0.490 ms, truncated to 0 by the ::bigint cast) and why they
--     average 13 ms. 896 node_completed rows / 7 days, ~128/day. Left
--     deriving: a wrong-by-construction number that says 'wallclock' is
--     strictly better than the same number with no label, and inventing a
--     measurement for it would be worse than both.
--
--   * Four sites pass a literal `0` for `wall_time_ms` because the node was
--     evaluated SYNCHRONOUSLY IN-PROCESS and no timer was started at all:
--     `route_system_node_output` (system-node rejection envelopes) plus the
--     verify / confidence-gate / dynamic-dispatch failure branches in
--     `run_scheduler_loop`. See the sentinel note below.
--
-- ── The `0` sentinel, which is the trap in this change ──────────────────
-- `NodeCompletionContext.wall_time_ms` documents `0` as "the engine didn't
-- record a start time", i.e. UNKNOWN, explicitly "rather than
-- 'instantaneous'". Binding that sentinel as a value would store a
-- real-looking `0 ms` — precisely the defect #707 caught with the pipeline
-- path's `0`, one table over.
--
-- It is worse here than it was there, because a `0` in THIS column is
-- already reachable honestly: the trigger's own `::bigint` cast truncates
-- every sub-millisecond derivation to 0, and 19 such rows exist today. A
-- sentinel stored as a measurement would be indistinguishable from them.
--
-- So the sentinel never becomes a value. `NodeEventWrite::monotonic_ms`
-- maps `0 -> None`, `None` means "the caller supplied nothing", and the
-- trigger derives exactly as it does today and labels the result
-- 'wallclock'. The mapping is pinned by `zero_wall_time_is_unknown_not_zero`
-- so it cannot be silently loosened.
--
-- ── Provenance, because the column becomes irreducibly mixed ────────────
-- This is #707's reasoning re-derived for this table, not copied: it
-- transfers because the same condition holds. After this change the column
-- holds monotonic values (~1 045 rows/day) and wall-clock derivations
-- (~130 rows/day) SIMULTANEOUSLY and permanently -- no cutover instant
-- separates them, because both keep arriving. A reader aggregating the
-- column without knowing which is which gets a mean of two different
-- quantities.
--
-- Rejected alternatives: a second column (`duration_monotonic_ms`) would
-- leave every existing reader still pointed at the wall-clock one, which is
-- the bug; caller-wins with no label would silently make the column mean two
-- things; and per-row inference from `log_message` (which is how the emit
-- sites were told apart to size this change) is a forensic accident, not an
-- interface.
--
-- The label vocabulary is deliberately IDENTICAL to
-- `module_executions.duration_source` so that a reader joining the two
-- tables has one vocabulary, and it carries #708's corrected meaning: it is
-- a CLOCK label ("read from an `Instant`, therefore suspend-proof"), NOT a
-- SPAN label. The spans differ between the two sites that supply a value --
-- `run_scheduler_loop` measures around the whole single-node dispatch future
-- while `dispatch_subworkflow` measures around a nested workflow run -- and
-- both are engine-side across-the-dispatch spans, the same class as
-- `module_executions`' `dispatch_started`. No new quantity enters the
-- column.
--
-- Existing rows are NOT rewritten and NOT relabelled. Their numbers were
-- produced by the old trigger and remain wall clock; NULL means "written
-- before the split", which is the honest label for them.

ALTER TABLE execution_events
    ADD COLUMN IF NOT EXISTS duration_source TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'execution_events_duration_source_check'
          AND conrelid = 'execution_events'::regclass
    ) THEN
        ALTER TABLE execution_events
            ADD CONSTRAINT execution_events_duration_source_check
            CHECK (duration_source IN ('monotonic', 'wallclock'));
    END IF;
END $$;

-- Caller-wins. `NEW.duration_ms IS NULL` is exactly "the caller supplied
-- nothing": this is a BEFORE INSERT trigger, so there is no OLD row and the
-- only way the field is non-NULL is that the INSERT named it.
--
-- NO CLAMP, and that is a checked conclusion rather than an omission.
-- #707 had to add `LEAST(..., 2147483647)` because
-- `module_executions.duration_ms` is `integer`, so its derivation raised
-- `integer out of range` INSIDE the trigger -- failing the whole statement
-- -- for any row open past 24.8 days, and the writers on that path are
-- exactly the ones that meet long-open rows. `execution_events.duration_ms`
-- is BIGINT (verified against the live schema), whose ceiling is 9.2e18 ms
-- ~ 292 million years, and the interval is bounded by the gap between two
-- rows of the same execution. The `::bigint` cast cannot overflow here.
-- The saturating conversion on the RUST side is still required and is
-- present: `wall_time_ms` is `u64`, whose top half does not fit `i64`.
CREATE OR REPLACE FUNCTION compute_execution_event_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.event_type IN ('node_completed', 'node_failed') AND NEW.node_id IS NOT NULL THEN
        IF NEW.duration_ms IS NULL THEN
            SELECT (EXTRACT(EPOCH FROM (NEW.created_at - ee.created_at)) * 1000)::bigint
            INTO NEW.duration_ms
            FROM execution_events ee
            WHERE ee.execution_id = NEW.execution_id
              AND ee.node_id = NEW.node_id
              AND ee.event_type = 'node_started'
            ORDER BY ee.created_at DESC
            LIMIT 1;
            -- Only label it if the lookup actually found a `node_started`.
            -- With no matching start row the SELECT ... INTO leaves
            -- `duration_ms` NULL, and a 'wallclock' label on a NULL value
            -- would claim a measurement that does not exist.
            IF NEW.duration_ms IS NOT NULL THEN
                NEW.duration_source := 'wallclock';
            END IF;
        END IF;
        -- Caller supplied a duration: leave BOTH columns exactly as bound.
        -- The writer, not this trigger, knows which clock it read; the
        -- engine's event sink binds 'monotonic' alongside the value, from
        -- the same parameter, so the two cannot disagree.
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Corrects the comment #707 left on this column. It said wall clock is "the
-- ONLY measurement available at INSERT time -- no writer supplies a duration
-- to this table". As of this migration a writer does, for ~89% of the rows
-- the trigger touches.
COMMENT ON COLUMN execution_events.duration_ms IS
    'Elapsed milliseconds from the matching node_started event to this '
    'completion event. READ duration_source BEFORE AGGREGATING: monotonic '
    'rows are real durations measured by the engine across the dispatch; '
    'wallclock rows are derived by compute_execution_event_duration() as a '
    'subtraction of two event timestamps and over-count by any host suspend '
    'in between; NULL-source rows (everything written before 2026-08-31) are '
    'wall clock from a period when the engine''s monotonic measurement never '
    'reached this table.';

COMMENT ON COLUMN execution_events.duration_source IS
    'Which clock produced duration_ms. ''monotonic'' = CLOCK_MONOTONIC, read '
    'from a std::time::Instant by the engine across the dispatch '
    '(run_scheduler_loop''s node_start_times for module nodes; '
    'dispatch_subworkflow''s dispatch_started for sub-workflow nodes); '
    'suspend-proof and trustworthy as a duration. ''wallclock'' = derived '
    'here by subtracting the node_started timestamp, which is the only value '
    'available for system nodes whose started/completed pair is emitted '
    'synthetically after the fact (emit_node_lifecycle_events) and for the '
    'four in-process evaluation paths that never start a timer. NULL = '
    'unknown: duration_ms is NULL, or the row predates this column. This is '
    'a CLOCK label, not a SPAN label -- see the note on '
    'module_executions.duration_source.';
