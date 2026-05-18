-- Approval gate for modules that require human approval before execution.
-- When a module's `requires_approval_for` list is non-empty, the engine
-- creates a pending approval record before dispatching.  Execution proceeds
-- only after the record is marked approved.

CREATE TABLE IF NOT EXISTS execution_approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id     UUID NOT NULL,
    execution_id    UUID NOT NULL,
    node_id         UUID NOT NULL,
    -- The operation categories that triggered the approval gate (e.g. "database_write", "external_http").
    required_for    TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied')),
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at      TIMESTAMPTZ,
    decided_by      UUID,  -- user who approved/denied
    reason          TEXT
);

-- Fast lookup: pending approvals for a given execution + node.
CREATE INDEX IF NOT EXISTS idx_execution_approvals_lookup
    ON execution_approvals (execution_id, node_id, status);

-- Dashboard query: all pending approvals for a workflow.
CREATE INDEX IF NOT EXISTS idx_execution_approvals_workflow_pending
    ON execution_approvals (workflow_id, status)
    WHERE status = 'pending';
