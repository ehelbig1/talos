-- Track replay lineage: which execution was replayed from which
ALTER TABLE workflow_executions ADD COLUMN IF NOT EXISTS replayed_from_id UUID REFERENCES workflow_executions(id);
CREATE INDEX IF NOT EXISTS idx_executions_replayed_from ON workflow_executions(replayed_from_id) WHERE replayed_from_id IS NOT NULL;
