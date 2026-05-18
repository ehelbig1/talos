-- Add workflow_type to workflows table.
-- Values:
--   production (default) — scored for readiness, appears in hygiene warnings
--   internal             — QA fixtures, tooling, scaffolding; suppressed from readiness scoring
--   test                 — automated test workflows; suppressed from readiness scoring
--   template             — reusable pattern library; scored for readiness but not for descriptions
--
-- The hygiene report only raises undescribed/uncapabilized warnings for production workflows,
-- eliminating phantom high-priority issues from QA artifacts.

ALTER TABLE workflows ADD COLUMN IF NOT EXISTS workflow_type TEXT NOT NULL DEFAULT 'production'
    CHECK (workflow_type IN ('production', 'internal', 'test', 'template'));

-- Index for hygiene report and filtered listing
CREATE INDEX IF NOT EXISTS idx_workflows_type ON workflows(user_id, workflow_type);
