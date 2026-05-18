-- Add 'agent' and 'agent-node' to the known capabilities constraint.
--
-- These capability strings were recognized in the Rust code (KNOWN_CAPABILITIES)
-- but missing from the database CHECK constraint, preventing the System Administrator
-- role from compiling agent-node modules needed for actor memory access.

ALTER TABLE agent_roles DROP CONSTRAINT IF EXISTS chk_known_capabilities;

ALTER TABLE agent_roles
    ADD CONSTRAINT chk_known_capabilities CHECK (
        allowed_capabilities <@ ARRAY[
            '*', 'admin',
            'minimal', 'minimal-node',
            'automation', 'automation-node',
            'network', 'network-node',
            'secrets', 'secrets-node', 'secrets:write',
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

-- Grant agent capability to System Administrator so it can compile
-- agent-node modules for actor memory workflows.
UPDATE agent_roles
   SET allowed_capabilities = array_append(allowed_capabilities, 'agent')
 WHERE name = 'System Administrator'
   AND NOT ('agent' = ANY(allowed_capabilities));
