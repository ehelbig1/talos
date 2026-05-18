-- Add flag to distinguish test/dry-run executions from real ones.
-- Test executions have a 30-second timeout and are cleaned up more aggressively.
ALTER TABLE workflow_executions ADD COLUMN IF NOT EXISTS is_test_execution BOOLEAN NOT NULL DEFAULT FALSE;

-- Index for fast cleanup of test executions
CREATE INDEX IF NOT EXISTS idx_workflow_executions_test ON workflow_executions (is_test_execution) WHERE is_test_execution = TRUE;
