-- Sync workflow_executions_archive with columns added to workflow_executions
-- after the archive table was originally created via LIKE workflow_executions INCLUDING ALL.
--
-- Missing columns:
--   priority          (added in 20260314001300_add_execution_priority.sql)
--   replayed_from_id  (added in 20260317000200 → actually 20260314001700_add_replay_tracking.sql)
--   input_data        (added in 20260317000200_add_execution_input_data.sql)
--
-- Without these columns, INSERT INTO workflow_executions_archive SELECT * FROM workflow_executions
-- fails with a column count mismatch even when zero rows are being archived.

ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'normal';

ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS replayed_from_id UUID REFERENCES workflow_executions(id) ON DELETE SET NULL;

ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS input_data JSONB;
