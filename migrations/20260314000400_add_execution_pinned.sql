ALTER TABLE workflow_executions ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE workflow_executions ADD COLUMN IF NOT EXISTS pin_note TEXT;
CREATE INDEX IF NOT EXISTS idx_workflow_executions_pinned ON workflow_executions (user_id, is_pinned) WHERE is_pinned = true;
