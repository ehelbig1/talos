ALTER TABLE workflow_executions ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'normal';
