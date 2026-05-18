-- Add 'waiting' to workflow_executions status constraint.
-- 'waiting' is used by the engine when a workflow pauses on an approval gate.
-- The status was never added to the CHECK constraint, causing silent UPDATE failures
-- that left approval-gated executions permanently stuck in 'running'.
ALTER TABLE workflow_executions DROP CONSTRAINT IF EXISTS workflow_executions_status_check;
ALTER TABLE workflow_executions ADD CONSTRAINT workflow_executions_status_check
    CHECK (status IN ('running', 'completed', 'failed', 'cancelled', 'queued', 'waiting'));
