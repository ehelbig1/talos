-- Add node_retrying as a distinct event type so retry attempts are
-- distinguishable from first-attempt node_started events in watch_execution
-- and get_execution_trace timelines.
ALTER TABLE execution_events DROP CONSTRAINT IF EXISTS execution_events_event_type_check;
ALTER TABLE execution_events ADD CONSTRAINT execution_events_event_type_check
    CHECK (event_type = ANY (ARRAY[
        'started', 'node_started', 'node_completed', 'node_failed',
        'node_skipped', 'node_waiting', 'node_retrying', 'completed', 'failed',
        'skipped', 'waiting', 'pending', 'loop_iteration'
    ]));
