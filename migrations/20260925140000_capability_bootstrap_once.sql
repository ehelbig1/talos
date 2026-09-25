-- The first-user capability bootstrap runs ONCE per deployment.
--
-- `talos_auth::promote_first_user_if_needed` runs at every controller boot and
-- after every signup. It used to treat "some user holds an `automation-node`
-- grant" as "already bootstrapped", so once the last such grant was removed the
-- next signup was elevated to the top of the capability lattice, and every
-- restart re-granted the earliest user. This row records that the bootstrap has
-- happened; the function reads it, never the grants.
--
-- One row at most (`singleton` is the primary key and can only be true).
-- `user_id` names the promoted user and is NULL for the backfill below. No
-- foreign key: deleting that user must not make the bootstrap run again.
CREATE TABLE IF NOT EXISTS capability_bootstrap (
    singleton    BOOLEAN     PRIMARY KEY DEFAULT true CHECK (singleton),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id      UUID,
    source       TEXT        NOT NULL CHECK (source IN ('runtime', 'backfill'))
);

-- Existing deployments: the bootstrap has already happened if anyone holds the
-- top ceiling now, or if the audit log shows it was granted or withdrawn. A
-- deployment with neither has never had a top-ceiling user (a fresh install, or
-- one waiting for its BOOTSTRAP_FIRST_USER_EMAIL operator to register) and
-- stays eligible. Grant revocations recorded before 2026-09-18 do not name the
-- withdrawn world, so they cannot count as evidence.
INSERT INTO capability_bootstrap (singleton, user_id, source)
SELECT true, NULL, 'backfill'
WHERE EXISTS (
        SELECT 1 FROM user_capability_grants
        WHERE max_capability_world = 'automation-node'
    )
   OR EXISTS (
        SELECT 1 FROM admin_event_log
        WHERE (event_type = 'capability_grant_issued'
               AND details->>'max_capability_world' = 'automation-node')
           OR (event_type = 'capability_grant_revoked'
               AND details->>'withdrawn_world' = 'automation-node')
    )
ON CONFLICT (singleton) DO NOTHING;
