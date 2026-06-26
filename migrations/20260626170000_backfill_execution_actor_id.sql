-- Phase E (part 1) of "every execution gets an actor": backfill any execution
-- row that predates the auto-stamp trigger / the actor-resolution dispatch
-- paths, so the data is universally attributed. This is the prerequisite for a
-- later migration to flip actor_id to NOT NULL on both tables.
--
-- Ordering: (1) guarantee every user has a default actor (some users may have
-- been skipped by the Phase B backfill's (user_id,'Default') ON CONFLICT if
-- they already had a manually-named 'Default' actor); (2) point every NULL
-- actor_id row at its user's default. After this, no execution row that has a
-- live owning user is left without an actor.

-- 1. Any user still missing a default actor gets one, with a collision-proof
--    name (the partial unique index already guarantees one default per user;
--    the suffix only avoids the (user_id, name) index when a plain 'Default'
--    is already taken). Idempotent: the WHERE NOT EXISTS skips users who now
--    have one.
INSERT INTO actors (id, user_id, name, description, max_capability_world, max_llm_tier, is_default)
SELECT gen_random_uuid(), u.id,
       'Default (' || left(u.id::text, 8) || ')',
       'Auto-provisioned fallback actor — ensures every execution has an owning actor.',
       'network-node', 'tier2', true
  FROM users u
 WHERE NOT EXISTS (SELECT 1 FROM actors a WHERE a.user_id = u.id AND a.is_default);

-- 2. Backfill straggler NULL actor_id rows to the user's default actor.
--    JOIN-UPDATE (not a correlated subquery) so it scales on large tables.
UPDATE workflow_executions we
   SET actor_id = a.id
  FROM actors a
 WHERE a.user_id = we.user_id AND a.is_default AND we.actor_id IS NULL;

UPDATE module_executions me
   SET actor_id = a.id
  FROM actors a
 WHERE a.user_id = me.user_id AND a.is_default AND me.actor_id IS NULL;
