-- The capability-grant column admits exactly the actor ceiling worlds
-- (package BR, 2026-09-16).
--
-- `user_capability_grants.max_capability_world` carried `ucg_world_check`
-- from 20260324000000: minimal, http, STANDARD, network, secrets, governance,
-- messaging, filesystem, cache, database, automation, FULL. The code's list of
-- valid ceilings is `talos_capability_world::ACTOR_CEILING_WORLDS`, and the two
-- drifted apart when MCP-816 / MCP-817 (2026-05-14) added `llm-node` and
-- `agent-node` to it and dropped the dead `standard-node` / `full-node` labels
-- from both grant handlers. Nobody widened this constraint, so:
--
--   * granting `llm-node` or `agent-node` — both accepted by the MCP
--     `grant_capability_ceiling` validator and the GraphQL
--     `grantCapabilityCeiling` validator — failed at the INSERT with 23514
--     and reached the caller as a generic "Failed to grant capability ceiling".
--     Measured on the reference deployment with rolled-back UPDATEs: both
--     refused, `database-node` / `automation-node` admitted. The least-privilege
--     ceiling for an agent actor could not be granted at all; the only grant
--     that covers one is `automation-node`, the top of the lattice.
--   * the dead `standard-node` and `full-node` were still STORABLE (by direct
--     SQL or an old row), where every gate reads them as `http-node` while the
--     self-reports would have rendered the raw label.
--
-- Existing rows holding a label outside the canonical list are rewritten to
-- `http-node` first — exactly what every gate already reads them as, so no
-- decision changes. Reference deployment: 1 row, `automation-node`, untouched.
-- `controller/tests/capability_grant_world_check_tests` pins this constraint's
-- set EQUAL to `ACTOR_CEILING_WORLDS`, so the next list change fails CI until
-- a migration follows it.

DO $$
DECLARE
    rewritten integer;
BEGIN
    UPDATE user_capability_grants
       SET max_capability_world = 'http-node'
     WHERE max_capability_world NOT IN (
        'minimal-node', 'http-node', 'llm-node', 'network-node', 'secrets-node',
        'governance-node', 'messaging-node', 'filesystem-node', 'cache-node',
        'database-node', 'agent-node', 'automation-node'
     );
    GET DIAGNOSTICS rewritten = ROW_COUNT;
    IF rewritten > 0 THEN
        RAISE NOTICE 'user_capability_grants: % row(s) held a non-canonical ceiling label and now read http-node, the value every gate already applied', rewritten;
    END IF;
END $$;

ALTER TABLE user_capability_grants DROP CONSTRAINT IF EXISTS ucg_world_check;
ALTER TABLE user_capability_grants ADD CONSTRAINT ucg_world_check CHECK (
    max_capability_world = ANY (ARRAY[
        'minimal-node', 'http-node', 'llm-node', 'network-node', 'secrets-node',
        'governance-node', 'messaging-node', 'filesystem-node', 'cache-node',
        'database-node', 'agent-node', 'automation-node'
    ]::text[])
);
