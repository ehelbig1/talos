CREATE TABLE IF NOT EXISTS workflow_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    workflow_id UUID NOT NULL,
    execution_id UUID NOT NULL,
    alert_type TEXT NOT NULL DEFAULT 'execution_failed',
    message TEXT NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alerts_user_unacked ON workflow_alerts(user_id, acknowledged) WHERE acknowledged = false;
