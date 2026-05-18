-- Add a CHECK constraint on agent_roles.allowed_capabilities to reject unknown
-- capability strings at INSERT/UPDATE time.
--
-- This is a defense-in-depth layer complementing the runtime validation in
-- mcp/auth.rs (warn_unknown_capabilities). The DB constraint prevents invalid
-- capability strings from being persisted in the first place, catching operator
-- typos (e.g. "admim" instead of "admin") before they silently downgrade access.
--
-- The constraint uses the PostgreSQL array containment operator (<@) which returns
-- true when every element of the left array is present in the right array.
-- An agent with allowed_capabilities = '{}' (empty) passes (no unknown elements).
--
-- To add new capabilities: update BOTH this migration (new migration, not an edit)
-- AND the KNOWN_CAPABILITIES constant in controller/src/mcp/auth.rs.

-- Verify no existing rows violate the constraint before adding it.
DO $$
DECLARE
    invalid_roles TEXT;
BEGIN
    SELECT string_agg(name, ', ')
    INTO invalid_roles
    FROM agent_roles
    WHERE NOT (allowed_capabilities <@ ARRAY[
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
        'trusted', 'trusted-node'
    ]::TEXT[]);

    IF invalid_roles IS NOT NULL THEN
        RAISE WARNING
            'The following agent roles have unrecognized capabilities and will be '
            'updated to remove unknown values before the constraint is applied: %',
            invalid_roles;
        -- Remove unknown capabilities from existing rows rather than blocking migration.
        -- The unknown values are replaced with the intersection of known capabilities.
        UPDATE agent_roles
        SET allowed_capabilities = ARRAY(
            SELECT unnest(allowed_capabilities)
            INTERSECT
            SELECT unnest(ARRAY[
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
                'trusted', 'trusted-node'
            ]::TEXT[])
        )
        WHERE NOT (allowed_capabilities <@ ARRAY[
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
            'trusted', 'trusted-node'
        ]::TEXT[]);
    END IF;
END $$;

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
            'trusted', 'trusted-node'
        ]::TEXT[]
    );
