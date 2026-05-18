CREATE TABLE IF NOT EXISTS workflow_sla_thresholds (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id uuid NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL,
    p95_latency_ms  bigint,
    success_rate_pct numeric(5,2),
    notification_webhook text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE(workflow_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_sla_thresholds_workflow ON workflow_sla_thresholds(workflow_id);
