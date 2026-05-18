-- Phase 1.1 / 2.1: Workflow runtime agents (distinct from mcp_agents API auth tokens).
-- A runtime agent is a named autonomous actor that owns workflows and executions,
-- enabling per-agent budgeting, governance, and audit trails.

CREATE TABLE IF NOT EXISTS agents (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    description          TEXT,
    -- active | suspended | terminated
    status               TEXT NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active', 'suspended', 'terminated')),
    -- Capability world ceiling: agents may not compile or run modules
    -- above this world without operator elevation.
    max_capability_world TEXT NOT NULL DEFAULT 'minimal-node',
    -- Explicit secret key_paths granted beyond the agent/{id}/* namespace.
    -- Set via grant_secret_access MCP tool.
    secret_grants        TEXT[] NOT NULL DEFAULT '{}',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata             JSONB
);

CREATE INDEX IF NOT EXISTS idx_agents_user_id ON agents(user_id);
CREATE INDEX IF NOT EXISTS idx_agents_active ON agents(user_id, status) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_user_name ON agents(user_id, name);

-- Per-agent budget policy (one row per agent, created on demand by set_agent_budget).
CREATE TABLE IF NOT EXISTS agent_budget_policies (
    agent_id                    UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    -- Rolling 1-hour execution cap. NULL = unlimited.
    max_executions_per_hour     INTEGER,
    -- Absolute lifetime execution cap. NULL = unlimited.
    max_executions_total        BIGINT,
    -- Per-node Wasm fuel ceiling (overrides WASM_FUEL_LIMIT for this agent). NULL = platform default.
    max_fuel_per_execution      BIGINT,
    -- Rolling 1-hour fuel cap across all executions. NULL = unlimited.
    max_fuel_per_hour           BIGINT,
    -- Rolling 1-hour outbound HTTP request cap. NULL = unlimited.
    max_outbound_requests_per_hour INTEGER,
    -- Maximum number of active (non-archived) workflows this agent may own. NULL = unlimited.
    max_workflow_count          INTEGER,
    -- Workflow creation rate limit (per minute). Default: 10.
    max_workflows_per_minute    INTEGER NOT NULL DEFAULT 10,
    -- Sandbox compilation rate limit (per hour, compilations are expensive). Default: 20.
    max_compilations_per_hour   INTEGER NOT NULL DEFAULT 20,
    -- Action when any budget ceiling is breached: suspend agent, alert only, or hard block.
    on_budget_exceeded          TEXT NOT NULL DEFAULT 'suspend'
                                    CHECK (on_budget_exceeded IN ('suspend', 'alert', 'block')),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$ BEGIN RAISE NOTICE 'agents + agent_budget_policies tables ready'; END $$;
