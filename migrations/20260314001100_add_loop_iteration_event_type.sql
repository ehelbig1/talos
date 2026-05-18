-- Allow loop_iteration as an execution event type
ALTER TABLE execution_events DROP CONSTRAINT IF EXISTS execution_events_event_type_check;
ALTER TABLE execution_events ADD CONSTRAINT execution_events_event_type_check
    CHECK (event_type = ANY (ARRAY[
        'started', 'node_started', 'node_completed', 'node_failed',
        'node_skipped', 'node_waiting', 'completed', 'failed',
        'skipped', 'waiting', 'pending', 'loop_iteration'
    ]));
