-- MCP-1203 (2026-05-17): drop the `secrets:write` string from the
-- `agent_roles.allowed_capabilities` CHECK constraint and strip it
-- from any rows that may carry it.
--
-- Context: MCP-1201 removed the five MCP secret-write handlers
-- (`handle_set_secret` / `handle_delete_secret` /
-- `handle_set_secret_namespace` / `handle_set_secret_expiry` /
-- `handle_rotate_secret`) and their `secrets:write` capability gate.
-- MCP is now read-only for secrets; the GraphQL surface
-- (`require_2fa + ApiKeyScope::SecretsWrite`) is the sole writer.
--
-- The `'secrets:write'` slot in the MCP-agent capability vocabulary
-- became dead the moment those handlers were removed. The original
-- MCP-1201 commit left this string in place to avoid migration risk,
-- but no agent role was ever seeded with it (the seeded-data gap was
-- the entire reason MCP-1201 was an architectural decision, not a
-- one-line role-grant fix). Stripping it now closes the cleanup —
-- future operators can't accidentally seed `secrets:write` on a role
-- expecting it to unlock MCP write surfaces.
--
-- IMPORTANT: this is the MCP-AGENT vocabulary (consumed by
-- `agent.has_capability(...)` on the `mcp_agents` auth path). The
-- API-KEY scope `ApiKeyScope::SecretsWrite` (talos-auth-types) is a
-- SEPARATE namespace, persisted on `api_keys.scopes`, and remains
-- ACTIVE — every GraphQL secret-write mutation still gates on it.
-- This migration does NOT touch `api_keys`.

-- 1. Defense-in-depth: strip 'secrets:write' from any agent_roles row
-- that has it. Idempotent — array_remove is a no-op when the value
-- is absent. Empty result-set is the expected case (no role was
-- ever seeded with this capability).
UPDATE agent_roles
   SET allowed_capabilities = array_remove(allowed_capabilities, 'secrets:write')
 WHERE 'secrets:write' = ANY(allowed_capabilities);

-- 2. Drop the existing CHECK constraint and re-add it without
-- 'secrets:write'. Mirrors the pattern in
-- 20260413150000_add_agent_capability_to_constraint.sql — drop +
-- re-add is the standard sqlx-compatible approach for amending a
-- table-level CHECK constraint.
ALTER TABLE agent_roles DROP CONSTRAINT IF EXISTS chk_known_capabilities;

ALTER TABLE agent_roles
    ADD CONSTRAINT chk_known_capabilities CHECK (
        allowed_capabilities <@ ARRAY[
            '*', 'admin',
            'minimal', 'minimal-node',
            'automation', 'automation-node',
            'network', 'network-node',
            'secrets', 'secrets-node',
            'filesystem', 'filesystem-node',
            'messaging', 'messaging-node',
            'database', 'database-node',
            'cache', 'cache-node',
            'governance', 'governance-node',
            'http', 'http-node',
            'llm-inference', 'llm-inference-node',
            'agent', 'agent-node',
            'trusted', 'trusted-node'
        ]::TEXT[]
    );
