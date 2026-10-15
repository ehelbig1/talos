-- Key `modules` and `webhook_triggers` row security on the USER, as every
-- other tenant table's policy is (security review 2026-10-15, D2-1).
--
-- 20260719120000 gave fourteen tables an ORG-keyed policy whose first arm is
-- `NULLIF(current_setting('app.current_org_ids', true), '') IS NULL` —
-- "no org context set → permit". 20260912140000 retired that shape on eleven
-- of them and 20261015100000 keyed `actor_memory` on its parent actor;
-- these two were never named. A transaction that sets the user but an EMPTY
-- org list — `begin_user_scoped`, and the guest-SQL transaction, which sets
-- the signed actor's owner and no orgs — reads that empty list as "unset" and
-- admits every tenant's rows. So `GRANT SELECT ON modules TO talos_guest`, the
-- documented way an operator lets `database`-world modules read a table,
-- showed every tenant's `source_code`, `config` and `allowed_secrets`; on
-- `webhook_triggers`, every tenant's verification-token hashes and routing.
--
-- SHAPE (20260912140000's): unset `app.current_user_id` → permit (the
-- engine, sweeps and the bare superuser pool are unchanged — a superuser
-- bypasses row security anyway); the row's `user_id` is the caller; or the
-- row's `org_id` is one of the caller's orgs (org sharing, read scope).
-- WITH CHECK: unset → permit; the caller's own row; or a row of the single
-- active org a write scope names (`app.current_org_id`, set together with
-- the user by `OrgScope`).
--
-- CATALOG ROWS (operator decision D2-A). A `modules` row with
-- `user_id IS NULL AND org_id IS NULL` is the shared catalog (registry or disk
-- seed), public by design — every user lists and installs from it — so it
-- stays readable under every scope, guest SQL included. It is NOT writable
-- under a scope: catalog rows are written only by the registry sync and the
-- seed, on the bare pool. `webhook_triggers` has no catalog: a row with
-- neither key is readable by no scoped caller.
--
-- `NULLIF(…, '')` on every GUC read: an empty string is "not set", never a
-- uuid cast error. Both tables already carry `(user_id)` and `(org_id, …)`
-- indexes (modules_user_kind_updated, modules_org_id, idx_modules_org;
-- idx_webhook_triggers_user_id, idx_webhook_triggers_org); none is added.
-- FORCE stays as 20260719120000 set it.

ALTER TABLE modules ENABLE ROW LEVEL SECURITY;
ALTER TABLE modules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS modules_tenant_isolation ON modules;
CREATE POLICY modules_tenant_isolation ON modules
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
    OR (user_id IS NULL AND org_id IS NULL)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

ALTER TABLE webhook_triggers ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_triggers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webhook_triggers_tenant_isolation ON webhook_triggers;
CREATE POLICY webhook_triggers_tenant_isolation ON webhook_triggers
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);
