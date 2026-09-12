-- RLS for the three tenant-content tables a SCOPED transaction reads and no
-- policy guards: `workflow_versions`, `execution_approvals`, `actor_action_log`.
--
-- Measured on the dev database 2026-09-12 (the fleet runs with
-- TALOS_RLS_SET_ROLE=true, so a `begin_*_scoped` transaction really does
-- `SET LOCAL ROLE talos_app` and the policies below really are evaluated):
--
--   * 83 public tables; 28 carry RLS. 37 of the other 55 have a `user_id` or
--     `org_id` column and NO policy — but on the largest of them the tenant
--     column was added by 20260529130000 and never written since:
--     execution_events 130 696 rows, org_id NULL on 130 696;
--     execution_cost_rollup 56 273 / 56 273; workflow_versions 165 / 165;
--     llm_usage 4 572 / 4 572; workflow_alerts 110 / 110; actor_action_log
--     102 / 102. The sibling template's `org_id IS NULL → permit` clause
--     would therefore admit EVERY row of every one of them. A policy on
--     these tables has to derive the tenant from the PARENT row, the way
--     20260904210000 derived the archive's tenant from `workflows`.
--   * Of the 37, exactly THREE are ever touched by a method that runs on a
--     caller-supplied scoped connection (`*_scoped` / `*_on_conn`, a
--     `&mut PgConnection` parameter): workflow_versions (five methods —
--     `list_versions_on_conn` and `get_active_*_on_conn` filter on
--     `workflow_id` ALONE, no owner predicate; `graph_json` is the tenant's
--     workflow definition), execution_approvals (two) and actor_action_log
--     (one, `WHERE actor_id = $1` alone). The other 34 are read only on the
--     bare pool, as the superuser, where a policy is never evaluated — a
--     policy there would be a control nothing exercises (check 58's dead
--     metric in RLS form), so they are RECORDED, not gated.
--
-- POLICY SHAPE — the tenant is the parent's tenant, and the parent's OWN
-- policy does the work. Under `talos_app` the `EXISTS (SELECT 1 FROM
-- workflows w WHERE w.id = <table>.workflow_id)` subquery is itself filtered
-- by `workflows_tenant_isolation` (user match OR org membership), so a child
-- row is visible exactly when its parent is — one rule, one home, no second
-- copy of the org-membership arithmetic to drift. `actor_action_log` derives
-- from `actors` the same way. The `NULLIF(current_setting(...), '') IS NULL`
-- clause keeps the unset→permit transition posture of every sibling policy
-- (a scoped role with no GUC is the engine/analytics path). Under the
-- superuser pool (BYPASSRLS) Postgres ignores the policy entirely and the
-- app-layer predicates remain the only scoping, exactly as before.
--
-- WITH CHECK is the same expression: a scoped INSERT/UPDATE may only land a
-- row whose parent the writer can see. `publish_version` and
-- `decide_execution_approval_scoped` write inside the caller's transaction
-- and pass by construction for the caller's own workflow; a write naming
-- another tenant's workflow is refused with 42501, which is the point.
--
-- Proved on a full copy of the dev database before this was written: as the
-- owning user under talos_app the counts are 165 / 6 / 102 (all rows, one
-- user owns the fleet); as a stranger 0 / 0 / 0; every scoped statement
-- plans as an index scan plus a hashed subplan, ≤ 0.03 ms.
-- FORCE so the policy also binds the table owner, matching every sibling.

ALTER TABLE workflow_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workflow_versions_tenant_isolation ON workflow_versions;
CREATE POLICY workflow_versions_tenant_isolation ON workflow_versions
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM workflows w WHERE w.id = workflow_versions.workflow_id)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM workflows w WHERE w.id = workflow_versions.workflow_id)
);

ALTER TABLE execution_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS execution_approvals_tenant_isolation ON execution_approvals;
CREATE POLICY execution_approvals_tenant_isolation ON execution_approvals
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM workflows w WHERE w.id = execution_approvals.workflow_id)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM workflows w WHERE w.id = execution_approvals.workflow_id)
);

ALTER TABLE actor_action_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE actor_action_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_action_log_tenant_isolation ON actor_action_log;
CREATE POLICY actor_action_log_tenant_isolation ON actor_action_log
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM actors a WHERE a.id = actor_action_log.actor_id)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM actors a WHERE a.id = actor_action_log.actor_id)
);
