-- Per-node execution timing
--
-- Adds server-side duration tracking to execution events. A trigger automatically
-- computes wall-clock duration from the most recent node_started event when a
-- node_completed or node_failed event is inserted. Zero engine code changes needed.

ALTER TABLE execution_events
    ADD COLUMN IF NOT EXISTS duration_ms BIGINT;

COMMENT ON COLUMN execution_events.duration_ms IS
    'Wall-clock duration in milliseconds from node_started to this completion event. Auto-computed by trigger. NULL for non-completion events.';

-- Trigger function: compute duration from the matching node_started event
CREATE OR REPLACE FUNCTION compute_execution_event_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.event_type IN ('node_completed', 'node_failed') AND NEW.node_id IS NOT NULL THEN
        SELECT (EXTRACT(EPOCH FROM (NEW.created_at - ee.created_at)) * 1000)::bigint
        INTO NEW.duration_ms
        FROM execution_events ee
        WHERE ee.execution_id = NEW.execution_id
          AND ee.node_id = NEW.node_id
          AND ee.event_type = 'node_started'
        ORDER BY ee.created_at DESC
        LIMIT 1;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_execution_event_duration
    BEFORE INSERT ON execution_events
    FOR EACH ROW
    EXECUTE FUNCTION compute_execution_event_duration();

-- Index to speed up the trigger's subquery (node_started lookup)
CREATE INDEX IF NOT EXISTS idx_exec_events_node_started
    ON execution_events (execution_id, node_id, event_type, created_at DESC)
    WHERE event_type = 'node_started';
