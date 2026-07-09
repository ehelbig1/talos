-- Guard against un-sanctioned write-ceiling GRANTS on `actors`.
--
-- Background: 20260709150000 grandfathered pre-existing actors with an
-- UNCONDITIONAL `UPDATE actors SET max_write_ceiling = 'write'`. That is
-- correct exactly once (sqlx applies each migration a single time), but if
-- that migration is ever re-applied — a `_sqlx_migrations` reset, a
-- disaster-recovery restore, a manual re-run — the blank UPDATE silently
-- re-grants `write` to EVERY actor, clobbering any `readonly` ceiling an
-- operator later set. Observed live on 2026-07-09: the migration re-applied
-- and flipped a deliberately-read-only actor back to `write`.
--
-- This trigger makes a `readonly -> write` escalation FAIL LOUD unless the
-- session explicitly opts in via the transaction-local GUC
-- `talos.allow_ceiling_grant = 'on'`. Only the sanctioned repository path
-- (`ActorRepository::set_actor_max_write_ceiling`) sets that GUC, so:
--   * operator grants via `set_actor_write_ceiling` keep working,
--   * locking an actor DOWN (`write -> readonly`) is always allowed (no GUC),
--   * a bulk/blind `UPDATE actors SET max_write_ceiling='write'` (the
--     grandfather footgun, or a fat-fingered manual query) aborts the
--     statement instead of silently corrupting operator intent.
--
-- On first apply of 20260709150000 the trigger does NOT exist yet (this
-- migration sorts AFTER it), so the one-time grandfather runs normally. The
-- guard only bites a LATER re-run — exactly the hazard.

CREATE OR REPLACE FUNCTION talos_guard_actor_write_ceiling()
    RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    -- Only guard the escalation to 'write'. write->readonly (locking down)
    -- and no-op writes (write->write) are always permitted.
    IF NEW.max_write_ceiling = 'write'
       AND OLD.max_write_ceiling IS DISTINCT FROM 'write'
       AND current_setting('talos.allow_ceiling_grant', true) IS DISTINCT FROM 'on'
    THEN
        RAISE EXCEPTION
            'refusing to grant write ceiling to actor % outside the sanctioned '
            'set_actor_write_ceiling path (guards against a bulk / migration re-run '
            'clobber of operator-set read-only actors)', NEW.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- CREATE OR REPLACE TRIGGER is idempotent on PostgreSQL 14+ (the deployed
-- image is pgvector:pg17). BEFORE UPDATE OF max_write_ceiling means the
-- trigger only fires when that column is actually in the UPDATE's SET list,
-- so ordinary actor updates pay nothing.
CREATE OR REPLACE TRIGGER actors_write_ceiling_grant_guard
    BEFORE UPDATE OF max_write_ceiling ON actors
    FOR EACH ROW
    EXECUTE FUNCTION talos_guard_actor_write_ceiling();
