-- Corrective migration for BUG-48 and BUG-49.
-- Migration 20260320000700 incorrectly set Redis Cache to 'network-node' and
-- Human Approval Gate to 'minimal-node'. Both are real Tier 3 WIT worlds
-- (governance-node, cache-node) defined in talos.wit and should be restored.
-- Also corrects Message Publisher to its proper messaging-node world.

-- BUG-48: Redis Cache is Tier 3d (cache-node), not network-node
UPDATE node_templates SET capability_world = 'cache-node'
WHERE name = 'Redis Cache' AND capability_world = 'network-node';

-- BUG-49: Human Approval Gate uses the governance WIT interface (Tier 3e)
UPDATE node_templates SET capability_world = 'governance-node'
WHERE name = 'Human Approval Gate' AND capability_world = 'minimal-node';

-- Message Publisher publishes to NATS (Tier 3c: messaging-node), not raw network
UPDATE node_templates SET capability_world = 'messaging-node'
WHERE name = 'Message Publisher' AND capability_world = 'network-node';
