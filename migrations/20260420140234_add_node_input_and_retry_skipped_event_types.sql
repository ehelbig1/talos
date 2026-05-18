-- Add `node_input` and `retry_skipped` event types to the execution_events
-- CHECK constraint.
--
-- The engine emits `node_input` from `engine_dispatch_single.rs:185` (captures
-- per-node input payloads for watch_execution + get_execution_trace) and
-- `retry_skipped` from `talos-workflow-engine-nats/src/dispatcher.rs:267` (when
-- the retry classifier decides a failure is non-retriable). Both were landing
-- in the `event_sink`'s WARN-and-drop path because the previous migration
-- (20260319000200) predated them. The event sink's drop is silent from the
-- engine's POV, so executions still run, but watch_execution + timeline tools
-- lose per-node input visibility and retry-skip signals.
--
-- Discovered while retesting workflow execution after the engine sync — every
-- test_workflow call produced a WARN log:
--   "Failed to persist execution event — dropped … event_type=node_input
--    check constraint \"execution_events_event_type_check\""

ALTER TABLE execution_events DROP CONSTRAINT IF EXISTS execution_events_event_type_check;
ALTER TABLE execution_events ADD CONSTRAINT execution_events_event_type_check
    CHECK (event_type = ANY (ARRAY[
        'started', 'node_started', 'node_completed', 'node_failed',
        'node_skipped', 'node_waiting', 'node_retrying', 'retry_skipped',
        'node_input', 'completed', 'failed',
        'skipped', 'waiting', 'pending', 'loop_iteration'
    ]));
