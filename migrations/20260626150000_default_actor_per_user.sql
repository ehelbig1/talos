-- Phase B of "every execution gets an actor": a default actor per user.
--
-- Adds an `is_default` marker (at most one per user via a partial unique
-- index) and backfills one default actor for every existing user. The default
-- actor is the fallback principal that `resolve_effective_actor` returns when
-- a dispatch carries no explicit actor — so every execution can be tied to a
-- real actor.
--
-- Policy (tunable; deliberately NON-breaking): the default actor ships
--   max_llm_tier        = 'tier2'        -- matches today's actor-less default
--   max_capability_world= 'network-node' -- covers the integration modules
--                                            (gmail/gcal/webhook need network + secrets)
-- Enforcement of these caps for the actor-less paths only begins in a later
-- phase; operators can tighten a default actor before then.

ALTER TABLE actors
    ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN actors.is_default IS
    'True iff this is the auto-provisioned fallback actor for the user. At most one per user (partial unique index idx_one_default_actor_per_user).';

-- At most one default actor per user.
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_default_actor_per_user
    ON actors (user_id) WHERE is_default;

-- Backfill: one default actor per existing user that doesn't already have one.
-- org_id is auto-stamped by trg_set_org_id (NULL-safe — leaves NULL when the
-- user has no personal org). ON CONFLICT (user_id, name) DO NOTHING guards the
-- rare collision with a pre-existing actor literally named 'Default'; those
-- users get a uniquely-named default lazily on first dispatch
-- (ActorRepository::get_or_create_default_actor).
INSERT INTO actors (id, user_id, name, description, max_capability_world, max_llm_tier, is_default)
SELECT gen_random_uuid(), u.id, 'Default',
       'Auto-provisioned fallback actor — ensures every execution has an owning actor.',
       'network-node', 'tier2', true
  FROM users u
 WHERE NOT EXISTS (
     SELECT 1 FROM actors a WHERE a.user_id = u.id AND a.is_default
 )
ON CONFLICT (user_id, name) DO NOTHING;
