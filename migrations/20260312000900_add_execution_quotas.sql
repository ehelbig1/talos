-- Per-organization resource quotas for multi-tenant cost control.
-- Enforced by the controller before dispatching jobs.

CREATE TABLE IF NOT EXISTS resource_quotas (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    -- Metric name: "concurrent_executions", "monthly_llm_tokens",
    -- "monthly_execution_hours", "module_compilations_per_hour", etc.
    metric          TEXT NOT NULL,
    -- Maximum allowed value (0 = unlimited).
    max_limit       BIGINT NOT NULL DEFAULT 0,
    -- Current usage in the billing period.
    current_usage   BIGINT NOT NULL DEFAULT 0,
    -- When the current usage counter resets (e.g. start of next month).
    resets_at       TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, metric)
);

CREATE INDEX IF NOT EXISTS idx_resource_quotas_org
    ON resource_quotas (org_id);

-- Dead letter queue for failed job dispatches that exhausted retries.
CREATE TABLE IF NOT EXISTS dead_letter_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id     UUID NOT NULL,
    execution_id    UUID NOT NULL,
    node_id         UUID NOT NULL,
    error_message   TEXT NOT NULL,
    payload         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL = not yet replayed; set when manually retried.
    replayed_at     TIMESTAMPTZ,
    replayed_by     UUID
);

CREATE INDEX IF NOT EXISTS idx_dlq_pending
    ON dead_letter_queue (created_at)
    WHERE replayed_at IS NULL;
