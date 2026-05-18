-- Security and audit improvements:
-- 1. Per-module secret scoping (allowed_secrets on templates and modules)
-- 2. Approval gate for destructive operations (requires_approval_for on templates)
-- 3. Persistent audit ledger table
-- 4. Retry policy on templates

-- ============================================================================
-- 1. Per-module secret scoping
-- ============================================================================

-- Templates declare which secrets they need (e.g., ["SLACK_TOKEN", "DB_PASS"]).
-- Modules inherit this from their template at instantiation time.
-- Empty array = no secrets required (deny all). ["*"] = allow all secrets.
ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS allowed_secrets TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE wasm_modules
    ADD COLUMN IF NOT EXISTS allowed_secrets TEXT[] NOT NULL DEFAULT '{}';

-- ============================================================================
-- 2. Approval gate for destructive operations
-- ============================================================================

-- Templates declare which operation types require human approval before execution.
-- Valid values: "database_write", "email_send", "external_http", "messaging"
-- Empty array = no approval required (default).
ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS requires_approval_for TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE wasm_modules
    ADD COLUMN IF NOT EXISTS requires_approval_for TEXT[] NOT NULL DEFAULT '{}';

-- ============================================================================
-- 3. Persistent audit ledger
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    workflow_id UUID NOT NULL,
    execution_id UUID NOT NULL,
    sequence_num BIGINT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    payload TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    UNIQUE(execution_id, sequence_num)
);

-- Index for querying audit trail by execution
CREATE INDEX IF NOT EXISTS idx_audit_events_execution
    ON audit_events(execution_id, sequence_num);

-- Index for querying audit trail by workflow
CREATE INDEX IF NOT EXISTS idx_audit_events_workflow
    ON audit_events(workflow_id, timestamp DESC);

-- Index for querying by action type (e.g., find all secret accesses)
CREATE INDEX IF NOT EXISTS idx_audit_events_action
    ON audit_events(action, timestamp DESC);

-- ============================================================================
-- 4. Retry policy on templates
-- ============================================================================

ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS max_retries INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS retry_backoff_ms BIGINT NOT NULL DEFAULT 500;
