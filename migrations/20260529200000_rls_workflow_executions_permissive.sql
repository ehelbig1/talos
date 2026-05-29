-- RFC 0004/0005 S2: enable RLS on `workflow_executions` in
-- PERMISSIVE-WHEN-UNSET mode.
--
-- workflow_executions is a HOT, high-write operational table with
-- legitimately cross-cutting internal readers (the engine's status
-- writes, analytics/cost rollups, the scheduler). So like workflows and
-- secrets it uses the permissive rollout: the user-facing GraphQL reads
-- (latest_workflow_executions, workflow_execution_history) are wired in
-- this PR to a tenant-scoped tx and get the RLS backstop ENFORCED; every
-- other path (engine writes, MCP repo reads that already scope by
-- user_id, analytics) stays permissive until the S3 dual-role work.
--
-- POLICY SHAPE — why EXISTS-on-workflows, not `org_id = ANY(...)`:
-- an execution's TENANT is its WORKFLOW's org, not the triggering user's
-- personal org. The M2 backfill (20260529130000) populated
-- workflow_executions.org_id from the owner's PERSONAL org (the generic
-- Group-A rule), and new rows aren't auto-stamped at all — so we.org_id
-- is NOT a reliable tenant key here. The user-facing reads never use it:
-- they filter `we.user_id = $me OR w.org_id = ANY($my_orgs)` against the
-- joined workflow. The policy mirrors that EXACTLY so it permits exactly
-- the app-layer set (no false-hide of a teammate's execution on an
-- org-shared workflow, and no false-admit). The EXISTS is an indexed PK
-- lookup on workflows.id and only runs on the enforced path — the
-- permissive `IS NULL` clause short-circuits it everywhere else. If the
-- workflow was deleted, EXISTS is false and only the owner (user_id)
-- clause matches — mirroring the app-layer LEFT JOIN's NULL w.org_id.
--
-- Safe in both role configs (non-superuser enforces the wired reads;
-- superuser bypasses + the existing app-layer WHERE still scopes; boot
-- guard flags the latter).

ALTER TABLE workflow_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_executions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS workflow_executions_tenant_isolation ON workflow_executions;
CREATE POLICY workflow_executions_tenant_isolation ON workflow_executions
USING (
    -- transition: un-wired path (engine writes / analytics / reset-to-'')
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    -- wired path → the owner sees their own executions …
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    -- … and org members see executions of workflows shared to their orgs
    -- (mirrors the app-layer `w.org_id = ANY($org_ids)` join clause).
    OR EXISTS (
        SELECT 1
        FROM workflows w
        WHERE w.id = workflow_executions.workflow_id
          AND w.org_id = ANY(
              string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
          )
    )
);
