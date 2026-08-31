-- `duration_source = 'monotonic'` is a claim about the CLOCK, not the SPAN.
-- Say so, and stop claiming otherwise.
--
-- ── The correction ──────────────────────────────────────────────────────
-- The comment written by 20260831120000 says 'monotonic' means the value was
--
--     "measured by the writer across the dispatch (engine single-node, loop
--      iteration, and pipeline-step paths)"
--
-- That is a SPAN claim, and it is false for one of the three paths it names.
-- The pipeline-step rows carry `PipelineStepResult::execution_time_ms`, which
-- the WORKER measures with its own `Instant` around ONE WASM step inside a
-- shared sandbox (`talos-worker-runtime::runtime` — `step_start.elapsed()`).
-- That does not span the dispatch: it excludes the NATS round trip, the queue
-- wait, and every other step in the same pipeline. A five-step pipeline
-- produces five rows whose durations sum to LESS than the one dispatch they
-- all came from, while a single-node row holds the whole dispatch. Told that
-- both were "measured across the dispatch", a reader would compare them
-- directly.
--
-- Nothing about the stored VALUES is wrong, and nothing is rewritten here.
-- What was wrong was the sentence describing them — which, on a column whose
-- entire purpose is to stop `duration_ms` from meaning two things silently,
-- is the same defect one level up.
--
-- ── What 'monotonic' does and does not guarantee ────────────────────────
-- DOES:     the number came from `std::time::Instant::elapsed()`, so it is
--           immune to host suspend and to wall-clock adjustment. This is the
--           property that matters, and the one the label was created for: on
--           this stack wall and monotonic have diverged by 8.1 hours, so a
--           'wallclock' row can be a nap length rather than a duration.
-- DOES NOT: fix WHICH span was measured. Two classes are in the column:
--
--   CONTROLLER-side dispatch span — the engine's `dispatch_started`
--   (`engine_dispatch_single.rs`), the loop path's `iter_started`
--   (`scheduler_handlers.rs`), and the webhook router's `wasm_start`
--   (`talos-webhooks::router`). Covers publish + queue + worker run + reply,
--   plus any dispatcher retry backoff and the one-shot OAuth credential
--   repair. This is the majority of rows.
--
--   WORKER-side step span — pipeline-step rows only, as described above.
--
-- Measured 2026-08-31 on 12 jobs paired by completion timestamp (engine value
-- in this column vs the worker's own `JobResult::execution_time_ms` for the
-- same job), the two clocks' spans differed by 5-14 ms, median 7 — the NATS
-- round trip. That is immaterial at the row level and is why one label is
-- still the right call. It is NOT a bound: the worker was idle, and the
-- controller-side span additionally contains queue wait and retry backoff,
-- which are unbounded under load.
--
-- PRACTICAL RULE for a reader: aggregate freely within a node; do not treat a
-- pipeline-step row's duration as commensurate with a single-node row's.

COMMENT ON COLUMN module_executions.duration_source IS
    'Which CLOCK produced duration_ms -- not which span. ''monotonic'' = read '
    'from std::time::Instant::elapsed(), therefore immune to host suspend and '
    'to wall-clock adjustment; trustworthy as a duration. ''wallclock'' = '
    'derived by calculate_module_execution_duration() as completed_at - '
    'started_at, the only measurement available to the stuck-execution sweep '
    'and the sibling-cancellation paths, and an over-count by exactly any '
    'suspend that occurred. NULL = unknown: duration_ms is NULL, or the row '
    'predates 2026-08-31. NOTE that ''monotonic'' spans two classes and they '
    'are not commensurate: most rows measure the CONTROLLER-side dispatch '
    '(engine single-node, loop iteration, webhook module dispatch -- publish '
    'through reply, including retry backoff), while pipeline-step rows carry '
    'the WORKER''s own timer around a single WASM step, which excludes the '
    'round trip and the pipeline''s other steps.';

COMMENT ON COLUMN module_executions.duration_ms IS
    'Elapsed milliseconds for this module execution. READ duration_source '
    'BEFORE AGGREGATING, for two separate reasons: wallclock rows over-count '
    'by any host suspend during the dispatch and NULL-source rows (everything '
    'written before 2026-08-31) are wall clock from a period when the '
    'engine''s monotonic measurement was discarded outright; and even among '
    'monotonic rows the measured span differs -- pipeline-step rows time one '
    'WASM step, every other path times the whole controller-side dispatch. '
    'See the duration_source comment.';
