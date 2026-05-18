-- Add lifecycle status to workflows: draft | active | archived
-- Scaffolded workflows start as 'draft'; publishing moves them to 'active'.
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS status varchar(20) NOT NULL DEFAULT 'draft';

-- Backfill: any workflow that has at least one active published version is 'active'.
UPDATE workflows
SET status = 'active'
WHERE id IN (
    SELECT DISTINCT workflow_id
    FROM workflow_versions
    WHERE is_active = true
);

CREATE INDEX IF NOT EXISTS idx_workflows_user_status ON workflows(user_id, status);
