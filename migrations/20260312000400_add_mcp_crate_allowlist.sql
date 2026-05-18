-- MCP crate dependency allowlist table.
-- Stores per-organization and global crate allowlist entries for MCP agent sandboxes.
-- Falls back to hardcoded defaults when the table is empty.

CREATE TABLE IF NOT EXISTS mcp_crate_allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    crate_name TEXT NOT NULL,
    max_version TEXT,  -- NULL = any version, specific value = max allowed
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    is_global BOOLEAN NOT NULL DEFAULT false,
    added_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(crate_name, org_id)
);

CREATE INDEX IF NOT EXISTS idx_mcp_crate_allowlist_org ON mcp_crate_allowlist(org_id);
CREATE INDEX IF NOT EXISTS idx_mcp_crate_allowlist_global ON mcp_crate_allowlist(is_global) WHERE is_global = true;
