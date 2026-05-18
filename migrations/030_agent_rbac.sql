-- Migration 030: Agent RBAC (Role-Based Access Control) for MCP

CREATE TABLE agent_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    -- JSON array of allowed WIT capability worlds (e.g. '["filesystem", "secrets"]')
    -- Using TEXT[] for simpler querying, or JSONB. TEXT[] is good.
    allowed_capabilities TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_agent_roles_updated_at
    BEFORE UPDATE ON agent_roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE mcp_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    role_id UUID NOT NULL REFERENCES agent_roles(id) ON DELETE RESTRICT,
    -- Cryptographically hashed bearer token for MCP connections
    token_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_connected_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_mcp_agents_updated_at
    BEFORE UPDATE ON mcp_agents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_mcp_agents_role_id ON mcp_agents(role_id);
CREATE INDEX idx_mcp_agents_token_hash ON mcp_agents(token_hash);

-- Pre-seed some default roles for convenience
INSERT INTO agent_roles (name, description, allowed_capabilities) VALUES
    ('System Administrator', 'God-mode agent with all capabilities', '{"minimal", "http", "network", "secrets", "filesystem", "messaging", "cache", "database", "governance", "trusted", "unknown"}'),
    ('Human Resources', 'HR agent that can access files and databases', '{"minimal", "filesystem", "database"}'),
    ('DevOps Auto-Remediation', 'DevOps agent that can access networks and messaging', '{"minimal", "http", "network", "messaging"}'),
    ('Financial Analyst', 'Read-only analyst agent', '{"minimal", "database"}');

