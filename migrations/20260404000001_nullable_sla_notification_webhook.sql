-- Make notification_webhook nullable on workflow_sla_thresholds.
-- Allows SLA thresholds to be configured for monitoring via get_workflow_sla_report
-- (API polling) without requiring a webhook URL.
ALTER TABLE workflow_sla_thresholds
    ALTER COLUMN notification_webhook DROP NOT NULL;
