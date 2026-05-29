-- RFC 0004 M4 step 2: enable RLS on user_module_pins, FAIL-CLOSED.
--
-- Same template as scratch_sessions (migration 20260529160000):
-- request-only table, all 3 query paths (pin / list in
-- talos-module-repository, list-with-install-status in
-- talos-advanced-repository) now run on a per-user scoped tx
-- (talos_db::begin_user_scoped / AdvancedRepository::user_scoped_tx), so
-- there is no un-wired path → straight to fail-closed.
--
-- Safe in both role configs (non-superuser enforces; superuser bypasses
-- and the existing `WHERE pm.user_id = $1` app filter still scopes — boot
-- guard flags that config). NULLIF guards handle the pooled-connection
-- GUC reset-to-'' case.

ALTER TABLE user_module_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_module_pins FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_module_pins_tenant_isolation ON user_module_pins;
CREATE POLICY user_module_pins_tenant_isolation ON user_module_pins
USING (
    user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(
         string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
       )
);
