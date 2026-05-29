-- RFC 0004 (Tenant = Organization) — auto-stamp org_id on the lower-volume
-- owned "definition" tables via a BEFORE INSERT trigger.
--
-- Rationale: actors / secrets / modules each have MANY create paths
-- (GraphQL, MCP, repo helpers, registry, clone, …). Stamping org_id at
-- every INSERT site is error-prone — one missed site leaves an
-- org_id-NULL row. A single trigger covers every path, current AND
-- future, in one place. It fires ONLY when org_id IS NULL, so an
-- explicit org (e.g. the GraphQL create_workflow Member+-checked path)
-- is never overridden; and it's NULL-tolerant — a global/registry
-- module with no owning user (user_id NULL, or no personal org) simply
-- keeps org_id NULL, which the membership-union read treats correctly.
--
-- Scope is deliberate: only these user-action-rate definition tables.
-- High-write operational tables (workflow_executions, *_events,
-- idempotency_keys, …) are NOT triggered — the per-insert subquery cost
-- isn't worth it there, their existing rows are M2-backfilled, and an
-- org_id-NULL row stays visible to its owner via the union read's
-- user_id clause. `workflows` already stamps org_id at every INSERT site
-- (PRs #10/#11), so it isn't triggered either.

-- Shared trigger function: populate org_id from the owner's personal org
-- when the inserting path didn't set it. The lookup hits the partial
-- unique index `idx_one_personal_org_per_owner` (O(1)).
CREATE OR REPLACE FUNCTION set_org_id_from_personal_org()
RETURNS trigger AS $$
BEGIN
    IF NEW.org_id IS NULL AND NEW.user_id IS NOT NULL THEN
        NEW.org_id := (
            SELECT id FROM organizations
            WHERE owner_id = NEW.user_id AND is_personal
            LIMIT 1
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_set_org_id ON actors;
CREATE TRIGGER trg_set_org_id BEFORE INSERT ON actors
    FOR EACH ROW EXECUTE FUNCTION set_org_id_from_personal_org();

DROP TRIGGER IF EXISTS trg_set_org_id ON secrets;
CREATE TRIGGER trg_set_org_id BEFORE INSERT ON secrets
    FOR EACH ROW EXECUTE FUNCTION set_org_id_from_personal_org();

DROP TRIGGER IF EXISTS trg_set_org_id ON modules;
CREATE TRIGGER trg_set_org_id BEFORE INSERT ON modules
    FOR EACH ROW EXECUTE FUNCTION set_org_id_from_personal_org();
