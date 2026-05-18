-- Allow operators to acknowledge known-bad executions so they are excluded
-- from the reliability score in get_readiness_breakdown.
-- Acknowledged failures remain in the history for audit purposes but are
-- treated as out-of-band events (e.g. deliberate config experiments, infra
-- incidents) rather than signal about the workflow's normal reliability.

ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS acknowledged_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS acknowledgement_reason TEXT;

-- Partial index: only rows that have been acknowledged (typically rare).
CREATE INDEX IF NOT EXISTS idx_executions_acknowledged
    ON workflow_executions (workflow_id, acknowledged_at)
    WHERE acknowledged_at IS NOT NULL;
