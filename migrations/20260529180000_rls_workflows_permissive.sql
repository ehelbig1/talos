-- RFC 0004 M4 — workflows enforcement, step 2: enable RLS on workflows
-- in PERMISSIVE-WHEN-UNSET mode.
--
-- workflows is a HOT, broadly-accessed table (read by GraphQL/MCP, the
-- engine on every execution, the scheduler). We can't fail-close it until
-- ALL those paths set the GUC, so we use the permissive rollout
-- (validated in talos-db/tests/rls_org_isolation.rs):
--   * Paths that set the GUC (now: the GraphQL workflow/workflows read
--     resolvers, wired in this PR via begin_tenant_read_scoped) get the
--     RLS backstop ENFORCED.
--   * Paths that don't (engine graph-load, scheduler poll, write paths,
--     un-wired resolvers/MCP handlers) hit the `IS NULL` clause →
--     PERMISSIVE → unchanged behaviour (no breakage).
-- Later steps wire the remaining paths; once all are wired the policy is
-- tightened (drop the `IS NULL` clause) to fail-closed.
--
-- Safe regardless of DB role: a non-superuser role enforces the wired
-- paths; a superuser/BYPASSRLS role bypasses RLS entirely and the
-- existing app-layer `WHERE user_id = $1 OR org_id = ANY(...)` filters
-- still scope (boot guard flags that config). NULLIF(...,'') handles the
-- pooled-connection GUC reset-to-'' case.

ALTER TABLE workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflows FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS workflows_tenant_isolation ON workflows;
CREATE POLICY workflows_tenant_isolation ON workflows
USING (
    -- transition: un-wired path (no GUC, or reset-to-'') → permissive.
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    -- wired path → enforce the membership union.
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(
         string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
       )
);
