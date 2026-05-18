-- Workflow-level human-in-the-loop approval gates.
--
-- An agent or workflow creates an approval gate with a secure random token.
-- A human (or automated system) visits the approval URL to approve or reject.
-- If a continuation_workflow_id is set, approving the gate automatically
-- triggers that workflow with the stored payload as its input.
--
-- This provides HITL support without requiring mid-WASM execution resumption:
-- Workflow A runs → creates gate → human approves → Workflow B triggers.

CREATE TABLE IF NOT EXISTS workflow_approval_gates (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL,
    title                   TEXT NOT NULL,
    description             TEXT,
    -- Arbitrary payload stored at gate creation, passed to continuation workflow on approval.
    payload                 JSONB NOT NULL DEFAULT '{}',
    status                  TEXT NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
    -- Cryptographically random URL-safe token (32 bytes hex = 64 chars).
    token                   TEXT NOT NULL UNIQUE,
    -- Optional: workflow to trigger when this gate is approved.
    continuation_workflow_id UUID REFERENCES workflows(id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    resolved_at             TIMESTAMPTZ,
    -- 'human_url', 'mcp_agent', or 'system'
    resolved_by_type        TEXT,
    resolved_by_note        TEXT,
    -- execution_id of the continuation workflow triggered on approval (if any)
    continuation_execution_id UUID
);

-- Fast lookup by token (used by approval URL handler)
CREATE INDEX IF NOT EXISTS idx_approval_gates_token
    ON workflow_approval_gates (token);

-- Dashboard: all pending gates for a user
CREATE INDEX IF NOT EXISTS idx_approval_gates_user_status
    ON workflow_approval_gates (user_id, status, created_at DESC)
    WHERE status = 'pending';

-- Cleanup: find expired pending gates
CREATE INDEX IF NOT EXISTS idx_approval_gates_expires
    ON workflow_approval_gates (expires_at)
    WHERE status = 'pending';
