-- Sync workflow_executions_archive with the acknowledged_at / acknowledgement_reason
-- columns added to workflow_executions in 20260322000004_add_execution_acknowledgment.sql.
-- The archive table uses SELECT * FROM the live table, so all columns must match exactly.

ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS acknowledged_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS acknowledgement_reason TEXT;
