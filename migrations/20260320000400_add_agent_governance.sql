-- Phase 4.1 / 4.3: Agent governance tables.
-- approval_policies: platform-injected HITL gates at execution time.
-- action_log: append-only human-readable audit trail of all agent activity.

-- Platform-level approval policies (injected by engine at trigger time,
-- not by the agent itself — removes the "did the agent remember to add approval?" gap).
CREATE TABLE IF NOT EXISTS agent_approval_policies (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id          UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- Built-in: 'new_external_host' | 'database_write' | 'email_send' |
    --           'first_workflow_deploy' | 'new_secret_access'
    -- Custom: any Rhai expression evaluated against node config at trigger time.
    trigger_condition TEXT NOT NULL,
    -- block: pause execution and create approval gate (like HITL module)
    -- notify: fire webhook but let execution continue
    -- log: record only (audit trail)
    approval_mode     TEXT NOT NULL DEFAULT 'block'
                          CHECK (approval_mode IN ('block', 'notify', 'log')),
    -- Email addresses or user IDs to notify. NULL = notify workflow owner only.
    approvers         TEXT[],
    created_at        TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_approval_policies_agent
    ON agent_approval_policies(agent_id);

-- Append-only human-readable audit trail. Answers "what did agent X do today?"
-- in a single query without cross-referencing raw execution traces.
CREATE TABLE IF NOT EXISTS agent_action_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    timestamp    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 'workflow_created' | 'workflow_executed' | 'secret_accessed' |
    -- 'external_request' | 'approval_requested' | 'approval_received' |
    -- 'budget_warning' | 'suspended' | 'terminated' | 'memory_written'
    action_type  TEXT NOT NULL,
    workflow_id  UUID,
    execution_id UUID,
    -- One-liner displayed in the action log UI / MCP get_agent_action_log response.
    summary      TEXT NOT NULL,
    -- Structured details (node configs, host names, secret paths, etc.)
    details      JSONB
);

-- Descending timestamp index for efficient recent-activity queries.
CREATE INDEX IF NOT EXISTS idx_agent_action_log_agent_ts
    ON agent_action_log(agent_id, timestamp DESC);

DO $$ BEGIN RAISE NOTICE 'agent_approval_policies + agent_action_log tables ready'; END $$;
