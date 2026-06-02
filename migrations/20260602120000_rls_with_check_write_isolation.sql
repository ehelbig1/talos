-- RLS write-isolation: add a WITH CHECK to the 6 tenant-isolation policies.
--
-- AUDIT (2026-06-02 RLS deep review): all 6 policies were `FOR ALL` with NO
-- `WITH CHECK`, so Postgres reused the read-oriented `USING` clause as the write
-- check. `USING` admits any row whose `org_id` is in the caller's MEMBERSHIP set
-- (`app.current_org_ids`) — so once RLS enforcement is enabled, a user could
-- INSERT a row into, or UPDATE a row's `org_id` to, ANY org they are a member of
-- (not just the single ACTIVE org the write context was scoped to), with no pin
-- to the acting user/org on the write side at all.
--
-- LATENT today: RLS enforces only when the controller connects via the
-- `talos_app` role (`TALOS_RLS_SET_ROLE`), which is OFF by default. This
-- migration is a no-op on a default deploy and takes effect when enforcement is
-- enabled — VALIDATE it as part of that enablement.
--
-- GUC CONTRACT (talos-db / talos-tenancy) — why the WITH CHECK differs per table:
--   * Writes via `begin_org_scoped`  set `app.current_org_id`  (the SINGLE active org)
--   * Writes via `begin_user_scoped` set `app.current_user_id` (per-user tables)
--   * READS set `app.current_user_id` + `app.current_org_ids`  (membership set)
-- A WITH CHECK that pinned `user_id = current_user_id` on the org-scoped tables
-- would BREAK their writes — that GUC is not set on `begin_org_scoped`. So each
-- table pins to the GUC ITS write path actually sets.
--
-- ROLLOUT-SAFE BY CONSTRUCTION: every clause is "<write GUC> unset → permit". The
-- WITH CHECK can therefore only ever RESTRICT a write when the GUC IS set (the
-- wired paths); it can never block an un-wired / mid-rollout / engine-bypass
-- write. If a per-table write-GUC assumption here is slightly off, the worst case
-- is "less restrictive than ideal", never "broken writes".

-- ── Org-scoped-write tables (begin_org_scoped → app.current_org_id) ──────────
-- A write must land in the single active org (or be org-less / personal).
ALTER POLICY workflows_tenant_isolation ON workflows
WITH CHECK (
    NULLIF(current_setting('app.current_org_id', true), '') IS NULL
    OR org_id IS NULL
    OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

ALTER POLICY secrets_tenant_isolation ON secrets
WITH CHECK (
    NULLIF(current_setting('app.current_org_id', true), '') IS NULL
    OR org_id IS NULL
    OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

ALTER POLICY actors_tenant_isolation ON actors
WITH CHECK (
    NULLIF(current_setting('app.current_org_id', true), '') IS NULL
    OR org_id IS NULL
    OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

-- ── User-scoped-write tables (begin_user_scoped → app.current_user_id) ───────
-- and workflow_executions (engine-written, owner = user_id; the engine path sets
-- no GUC, so the unset→permit clause keeps engine writes working).
-- A write must be owned by the acting user.
ALTER POLICY scratch_sessions_tenant_isolation ON scratch_sessions
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER POLICY user_module_pins_tenant_isolation ON user_module_pins
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER POLICY workflow_executions_tenant_isolation ON workflow_executions
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);
