-- Workflow versions table
CREATE TABLE IF NOT EXISTS workflow_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    graph_json JSONB NOT NULL,
    description TEXT,
    published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_by UUID NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(workflow_id, version_number)
);

-- Track which version an execution used
ALTER TABLE workflow_executions
ADD COLUMN IF NOT EXISTS workflow_version_id UUID REFERENCES workflow_versions(id);

CREATE INDEX IF NOT EXISTS idx_workflow_versions_active
ON workflow_versions(workflow_id)
WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_workflow_versions_workflow
ON workflow_versions(workflow_id, version_number DESC);
