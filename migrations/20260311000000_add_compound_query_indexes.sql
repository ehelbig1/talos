-- Compound indexes for common query patterns
-- Note: For production, run these with CONCURRENTLY outside of a transaction.
CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow_created
    ON workflow_executions(workflow_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_workflow_executions_user_status_created
    ON workflow_executions(user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_module_executions_user_module_started
    ON module_executions(user_id, module_id, started_at DESC);
