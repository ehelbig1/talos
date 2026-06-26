-- Phase D2 of "every execution gets an actor": auto-stamp the user's default
-- actor on any execution row inserted without one.
--
-- The trigger/dispatch surface that creates workflow_executions / module_
-- executions rows is large (the main trigger path, scheduler, webhooks,
-- continuation, workflow-chains, enqueue, replay, test runs, …). Rather than
-- thread default-actor resolution through every Rust INSERT site — churn-heavy
-- and easy to miss a path — stamp it at the DB layer, mirroring the existing
-- `trg_set_org_id` (`set_org_id_from_personal_org`) auto-stamp trigger that
-- already fills org_id the same way.
--
-- The trigger fires ONLY when actor_id IS NULL, so any caller that already
-- resolves an actor (the gmail/gcal/webhook dispatch, the in-workflow module
-- store, the D2.1 main trigger path) is untouched. The lookup is O(1) via the
-- partial unique index idx_one_default_actor_per_user. NULL-safe: a user with
-- no default actor (only possible transiently before the Phase B backfill /
-- signup hook runs) keeps actor_id NULL, exactly like the org_id trigger.
--
-- This makes attribution universal, which is the prerequisite for a later
-- migration to flip actor_id to NOT NULL on both tables.

CREATE OR REPLACE FUNCTION set_default_actor_on_execution()
RETURNS trigger AS $$
BEGIN
    IF NEW.actor_id IS NULL AND NEW.user_id IS NOT NULL THEN
        NEW.actor_id := (
            SELECT id FROM actors
            WHERE user_id = NEW.user_id AND is_default
            LIMIT 1
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_set_default_actor ON workflow_executions;
CREATE TRIGGER trg_set_default_actor BEFORE INSERT ON workflow_executions
    FOR EACH ROW EXECUTE FUNCTION set_default_actor_on_execution();

DROP TRIGGER IF EXISTS trg_set_default_actor ON module_executions;
CREATE TRIGGER trg_set_default_actor BEFORE INSERT ON module_executions
    FOR EACH ROW EXECUTE FUNCTION set_default_actor_on_execution();
