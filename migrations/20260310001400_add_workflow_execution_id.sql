-- Add workflow_execution_id column to module_executions to link individual
-- module runs back to the parent workflow execution.
ALTER TABLE module_executions
    ADD COLUMN IF NOT EXISTS workflow_execution_id UUID;

-- Index for looking up all module executions within a workflow run.
CREATE INDEX IF NOT EXISTS idx_module_executions_workflow_exec
    ON module_executions (workflow_execution_id)
    WHERE workflow_execution_id IS NOT NULL;
