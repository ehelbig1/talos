-- Bootstrap: grant the first registered user the 'automation-node' ceiling
-- so they can administer capability grants for other users.
-- This is idempotent — ON CONFLICT updates the existing grant.
INSERT INTO user_capability_grants (user_id, max_capability_world, notes)
SELECT id, 'automation-node', 'Bootstrap: first-user admin grant'
FROM users
ORDER BY created_at ASC
LIMIT 1
ON CONFLICT (user_id) DO UPDATE
SET max_capability_world = EXCLUDED.max_capability_world,
    granted_at = now(),
    notes = EXCLUDED.notes
WHERE user_capability_grants.max_capability_world != 'automation-node';
