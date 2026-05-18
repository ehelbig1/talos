-- Add user_id to mcp_agents for resource scoping.
-- MCP agents can optionally be associated with a user to restrict
-- which resources (executions, modules, etc.) they can access.
ALTER TABLE mcp_agents ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_agents_user_id ON mcp_agents(user_id);
