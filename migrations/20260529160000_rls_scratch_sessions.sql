-- RFC 0004 (Tenant = Organization) — M4 step 1: enable RLS on the FIRST
-- table, scratch_sessions, FAIL-CLOSED.
--
-- Why this table first: it is request-only (no worker / execution-time
-- access) and every query lives in talos-advanced-repository, all of
-- which are now wired to run on a per-user tenant-scoped transaction
-- (`user_scoped_tx`, which sets app.current_user_id). So there is no
-- un-wired path — we can go straight to a fail-closed policy rather than
-- the permissive-then-tighten rollout the broader tables will use.
--
-- Safety in BOTH role configurations:
--   * Non-superuser app role (production target): RLS enforces — the
--     wired methods set app.current_user_id, so the owner sees/modifies
--     only their own sessions; another user's GUC never matches.
--   * Superuser / BYPASSRLS app role (simple deploys): Postgres bypasses
--     RLS entirely, so nothing changes — and the methods' existing
--     `WHERE user_id = $1` app-layer filter still scopes. The boot guard
--     (warn_if_rls_will_be_bypassed) flags this configuration.
--
-- Policy mirrors the membership-union shape (scratch sessions are
-- personal, so in practice only the user_id clause matches; the org
-- clause is kept for uniformity with the other tables' policies). The
-- NULLIF(...,'') guards handle the custom-GUC reset-to-'' on pooled
-- connections (see talos-db/tests/rls_org_isolation.rs).

ALTER TABLE scratch_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE scratch_sessions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scratch_sessions_tenant_isolation ON scratch_sessions;
CREATE POLICY scratch_sessions_tenant_isolation ON scratch_sessions
USING (
    user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(
         string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
       )
);
