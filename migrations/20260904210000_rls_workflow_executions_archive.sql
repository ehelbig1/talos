-- RLS on `workflow_executions_archive` — the tier the tenant-isolation
-- rollout never reached.
--
-- Measured on the dev database 2026-09-04, hours after #746's first real
-- archival pass:
--
--   pg_class    workflow_executions          relrowsecurity=t  relforcerowsecurity=t
--               workflow_executions_archive  relrowsecurity=f  relforcerowsecurity=f
--   pg_policies workflow_executions          1 policy (workflow_executions_tenant_isolation)
--               workflow_executions_archive  0 policies
--
-- Until #746 that gap was academic: the archive had held ZERO rows across the
-- platform's entire history (the archival statement was a parse error on every
-- tick since 2026-03-26, and the error was discarded). A table with no rows
-- needs no row-level security. As of the first successful pass it holds 96 real
-- tenant executions — with their `output_data_enc` ciphertext and the
-- `output_enc_key_id` naming the DEK that opens it — and the ONLY thing scoping
-- any read of it is an application-level `AND user_id = $2`.
--
-- Checks 25/42 exist precisely so that predicate is never the only layer. Every
-- other execution read runs on a `begin_user_scoped` transaction with the RLS
-- policy as the backstop once `TALOS_RLS_SET_ROLE` is on. This migration gives
-- the archive the same second layer, and it lands together with the reader that
-- makes archived rows reachable by id (`ExecutionRepository::lookup_execution`)
-- rather than after it.
--
-- POLICY SHAPE — copied clause-for-clause from
-- `20260529200000_rls_workflow_executions_permissive.sql`, not re-derived.
-- Its rationale carries over verbatim, because the archive is column-for-column
-- identical to the live table:
--
--   * `NULLIF(current_setting(...), '') IS NULL` → permissive when unset. The
--     retention sweep, analytics and the boot-time pass are un-wired paths that
--     set no GUC; without this clause the sweep could not write to the archive
--     at all. Same transition posture as the live table.
--   * `user_id = app.current_user_id` → the owner sees their own executions.
--   * `EXISTS (SELECT 1 FROM workflows w WHERE w.id = <table>.workflow_id AND
--     w.org_id = ANY(app.current_org_ids))` → an execution's TENANT is its
--     WORKFLOW's org, not the triggering user's personal org. The archive's own
--     `org_id` column is as unreliable a tenant key as the live table's (it was
--     backfilled from the owner's PERSONAL org and new rows inherit whatever
--     the live row carried — the archived row observed on the dev DB has
--     `org_id IS NULL` while its workflow has an org), so the policy joins to
--     `workflows` exactly as the live one does. If the workflow was deleted the
--     EXISTS is false and only the owner clause matches — which is the correct
--     and intended outcome for an archived row whose workflow is gone.
--
-- WITH CHECK mirrors `20260602120000_rls_with_check_write_isolation.sql`'s
-- clause for `workflow_executions`: a write must be owned by the acting user,
-- with the same unset→permit transition clause so the sweep's INSERT works.
--
-- Safe in both role configs: under a superuser/BYPASSRLS pool (the default,
-- `TALOS_RLS_SET_ROLE` off) Postgres ignores the policy and the app-layer
-- `AND user_id = $2` still scopes every read; under `talos_app` the policy
-- enforces. FORCE is applied so the policy also binds the table owner, matching
-- the live table.

ALTER TABLE workflow_executions_archive ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_executions_archive FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS workflow_executions_archive_tenant_isolation
    ON workflow_executions_archive;
CREATE POLICY workflow_executions_archive_tenant_isolation ON workflow_executions_archive
USING (
    -- transition: un-wired path (retention sweep / analytics / reset-to-'')
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    -- wired path → the owner sees their own archived executions …
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    -- … and org members see archived executions of workflows shared to their
    -- orgs (mirrors the live policy's join clause exactly).
    OR EXISTS (
        SELECT 1
        FROM workflows w
        WHERE w.id = workflow_executions_archive.workflow_id
          AND w.org_id = ANY(
              string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
          )
    )
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

-- No new index: the by-id read filters `id = $1 AND user_id = $2` and the
-- archive already carries `workflow_executions_archive_pkey` on `id` plus
-- `workflow_executions_archive_user_id_idx` (both inherited from the original
-- `LIKE workflow_executions INCLUDING ALL`). Verified against the live schema.
