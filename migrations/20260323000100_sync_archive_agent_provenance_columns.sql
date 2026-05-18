-- Sync workflow_executions_archive with agent_id and provenance columns
-- added to workflow_executions in 20260320000500_add_agent_workflow_association.sql.
-- These were never synced to the archive table, causing SELECT * INSERT to fail.

ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS agent_id   UUID,
    ADD COLUMN IF NOT EXISTS provenance JSONB;
