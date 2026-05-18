-- Migration: Add workflow suspensions table
-- Enables arbitrary pause/resume of workflow execution for external callbacks
-- (72h ETL jobs, polling-required APIs, etc.). The correlation_id IS the bearer token.

CREATE TABLE IF NOT EXISTS workflow_suspensions (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    execution_id             UUID,
    correlation_id           TEXT        NOT NULL,  -- 64 hex chars (32 random bytes)
    description              TEXT,
    continuation_workflow_id UUID        REFERENCES workflows(id) ON DELETE SET NULL,
    state                    JSONB,
    status                   TEXT        NOT NULL DEFAULT 'waiting'
                                         CHECK (status IN ('waiting','resumed','expired','cancelled')),
    timeout_at               TIMESTAMPTZ,
    resumed_at               TIMESTAMPTZ,
    resumed_by               TEXT,       -- 'callback_url' | 'mcp_tool' | 'timeout_expiry'
    resumed_payload          JSONB,
    callback_url             TEXT        NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (correlation_id)
);

CREATE INDEX IF NOT EXISTS idx_suspensions_waiting ON workflow_suspensions(correlation_id) WHERE status = 'waiting';
CREATE INDEX IF NOT EXISTS idx_suspensions_user    ON workflow_suspensions(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_suspensions_timeout ON workflow_suspensions(timeout_at) WHERE status = 'waiting' AND timeout_at IS NOT NULL;
