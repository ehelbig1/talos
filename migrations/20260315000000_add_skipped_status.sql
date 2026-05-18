-- Allow 'Skipped' as an execution event status
ALTER TABLE execution_events DROP CONSTRAINT IF EXISTS execution_events_status_check;
ALTER TABLE execution_events ADD CONSTRAINT execution_events_status_check
    CHECK (status = ANY (ARRAY['Running', 'Completed', 'Failed', 'Skipped']));
