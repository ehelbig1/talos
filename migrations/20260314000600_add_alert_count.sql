-- Alert deduplication: add occurrence count and last-occurred timestamp
ALTER TABLE workflow_alerts ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE workflow_alerts ADD COLUMN IF NOT EXISTS last_occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Deduplicate alerts: same workflow + same error message = same alert (only for unacknowledged)
CREATE UNIQUE INDEX IF NOT EXISTS unique_alert_workflow_message
ON workflow_alerts(workflow_id, message) WHERE acknowledged = false;
