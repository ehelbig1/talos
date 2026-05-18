-- Add checkpoint_data to workflow_executions for resilience
ALTER TABLE workflow_executions ADD COLUMN IF NOT EXISTS checkpoint_data JSONB;

COMMENT ON COLUMN workflow_executions.checkpoint_data IS 'Stores intermediate results and state for resilient workflow resumption.';
