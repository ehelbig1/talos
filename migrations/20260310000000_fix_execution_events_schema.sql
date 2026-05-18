-- Fix execution_events table to support all event types and iteration tracking
ALTER TABLE execution_events ADD COLUMN IF NOT EXISTS iteration_index INTEGER;
ALTER TABLE execution_events ADD COLUMN IF NOT EXISTS iteration_total INTEGER;

-- Expand the event_type check constraint to include all possible event types
ALTER TABLE execution_events DROP CONSTRAINT IF EXISTS execution_events_event_type_check;
ALTER TABLE execution_events ADD CONSTRAINT execution_events_event_type_check
    CHECK (event_type = ANY (ARRAY[
        'started', 'node_started', 'node_completed', 'node_failed',
        'node_skipped', 'node_waiting', 'completed', 'failed',
        'skipped', 'waiting', 'pending'
    ]));
