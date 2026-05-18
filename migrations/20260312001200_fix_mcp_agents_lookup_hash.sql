-- Add the token_lookup_hash column that the MCP auth middleware expects.
-- This is a SHA-256 hash of the plaintext token, used for fast DB lookup
-- before the slower bcrypt verification.

ALTER TABLE mcp_agents
    ADD COLUMN IF NOT EXISTS token_lookup_hash TEXT;

-- Index for fast lookup during auth
CREATE INDEX IF NOT EXISTS idx_mcp_agents_token_lookup_hash
    ON mcp_agents (token_lookup_hash)
    WHERE token_lookup_hash IS NOT NULL;
