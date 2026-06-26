-- Phase E (part 2) of "every execution gets an actor": flip actor_id to NOT NULL
-- on both execution tables and harden the FK.
--
-- Safe because: the E.1 backfill (20260626170000, runs immediately before this)
-- left zero NULL actor_id rows and ensured every user has a default actor; and
-- the trg_set_default_actor BEFORE-INSERT trigger (20260626160000) stamps the
-- default on any future actor-less insert. Together they guarantee the column
-- is always populated, so the constraint can never be violated at runtime.
--
-- FK: `ON DELETE SET NULL` is incompatible with NOT NULL (a hard actor delete
-- would try to NULL a NOT-NULL column and error). Switch to ON DELETE RESTRICT,
-- which also matches the actor lifecycle — actors are SOFT-deleted (status
-- 'terminated'/'archived'), never hard-DELETEd, so the FK never actually fires;
-- RESTRICT just makes "you can't hard-delete an actor that owns executions"
-- explicit instead of silently orphaning the attribution.
--
-- The existing FK is named after the pre-rename `agent_id` column
-- (workflow_executions_agent_id_fkey) and module_executions' was auto-named in
-- Phase A — so drop whatever FK→actors exists on each table by lookup, then add
-- a canonically-named RESTRICT one.

DO $$
DECLARE
    cname text;
BEGIN
    SELECT conname INTO cname FROM pg_constraint
     WHERE contype = 'f' AND conrelid = 'workflow_executions'::regclass
       AND confrelid = 'actors'::regclass;
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE workflow_executions DROP CONSTRAINT %I', cname);
    END IF;
    ALTER TABLE workflow_executions
        ADD CONSTRAINT workflow_executions_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES actors(id) ON DELETE RESTRICT;

    SELECT conname INTO cname FROM pg_constraint
     WHERE contype = 'f' AND conrelid = 'module_executions'::regclass
       AND confrelid = 'actors'::regclass;
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE module_executions DROP CONSTRAINT %I', cname);
    END IF;
    ALTER TABLE module_executions
        ADD CONSTRAINT module_executions_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES actors(id) ON DELETE RESTRICT;
END $$;

ALTER TABLE workflow_executions ALTER COLUMN actor_id SET NOT NULL;
ALTER TABLE module_executions ALTER COLUMN actor_id SET NOT NULL;
