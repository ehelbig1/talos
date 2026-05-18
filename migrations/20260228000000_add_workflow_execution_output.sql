-- Add output_data to workflow_executions
ALTER TABLE workflow_executions ADD COLUMN IF NOT EXISTS output_data JSONB;
