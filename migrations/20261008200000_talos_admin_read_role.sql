-- A least-privilege role for the platform-admin `query_paginated` tool
-- (2026-10-08; docs/engineering-log/packages/2026-10-08-query-paginated-admin-read-role.md).
--
-- `query_paginated` runs SQL its caller writes. Since 2026-10-08 the statement
-- is parsed and must be one read that calls only allow-listed functions and
-- names only public tables that are not withheld (talos-admin-query-gate), and
-- it runs inside `BEGIN READ ONLY` on a connection that is closed afterwards.
-- It still ran as the pool's role, a superuser on the operator's deployment.
-- `AdvancedRepository::execute_paginated_select` now enters this role with
-- `SET LOCAL ROLE talos_admin_read` before the caller's statement, and refuses
-- (never falls back to the pool's role) when it cannot.
--
-- ## What the role holds
--
-- * NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT, member of nothing.
-- * BYPASSRLS. The tool reads across tenants by design, and the policies on
--   the row-secured tables are written for the application's tenant context:
--   measured on a migrated database, a role WITHOUT it read 0 of 2
--   `scratch_sessions` rows (silently), and a policy granting it every row
--   would make it need SELECT on whatever that table's policy subqueries read
--   (`workflow_executions`'s reads `workflows`). With BYPASSRLS no policy is
--   evaluated. The repository REFUSES to run as a role that lacks it, so a
--   read never returns fewer rows than exist.
-- * USAGE on schema public, and SELECT on the tables and views below, by
--   name. Nothing on a table in `BLOCKED_TABLES_LIST`
--   (talos-admin-query-gate); nothing on a sequence; no column grants; NO
--   default privileges, so a table a later migration creates is unreadable
--   through the tool until a migration grants it.
--   `talos-advanced-repository/tests/admin_read_role_grants.rs` holds both
--   halves against the migrated schema: no privilege on a withheld table, and
--   every relation in public granted or withheld.
--
-- ## A managed Postgres
--
-- CREATE ROLE needs CREATEROLE, and BYPASSRLS needs a superuser (or, from
-- Postgres 16, a CREATEROLE role that has BYPASSRLS itself). Where the
-- migrating user cannot, this migration creates what it can and says so in a
-- NOTICE; the tool then refuses with a message naming what to run:
--
--     CREATE ROLE talos_admin_read NOLOGIN NOINHERIT BYPASSRLS;  -- as a superuser
--     GRANT talos_admin_read TO <the pool's role>;
--     -- and the GRANT statements below
--
-- A new table the tool should read: `GRANT SELECT ON public.<t> TO
-- talos_admin_read;` in that table's migration, or add it to
-- BLOCKED_TABLES_LIST. The grants test fails until one of the two is done.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_admin_read') THEN
        BEGIN
            CREATE ROLE talos_admin_read
                NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
        EXCEPTION WHEN insufficient_privilege THEN
            BEGIN
                CREATE ROLE talos_admin_read
                    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                RAISE NOTICE 'talos_admin_read created WITHOUT BYPASSRLS (insufficient privilege): '
                    'query_paginated refuses until a superuser runs ALTER ROLE talos_admin_read BYPASSRLS';
            EXCEPTION WHEN insufficient_privilege THEN
                RAISE NOTICE 'talos_admin_read not created (insufficient privilege): query_paginated '
                    'refuses until it exists; see migrations/20261008200000_talos_admin_read_role.sql';
            END;
        END;
    END IF;
END$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_admin_read') THEN
        RETURN;
    END IF;
    -- A role an operator made by hand may not be the migrating user's to
    -- comment on or grant. Neither failure may stop the controller booting
    -- (it applies migrations at start-up and refuses to start on an error):
    -- the tool refuses instead, with the commands to run.
    BEGIN
        COMMENT ON ROLE talos_admin_read IS
            'The role query_paginated runs its caller''s SQL as (SET LOCAL ROLE). '
            'SELECT on named public tables only; see migrations/20261008200000_talos_admin_read_role.sql.';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'talos_admin_read: no privilege to comment on the role; skipped';
    END;
    -- The pool's role must be a member for SET LOCAL ROLE to succeed.
    IF CURRENT_USER <> 'talos_admin_read' THEN
        BEGIN
            EXECUTE format('GRANT talos_admin_read TO %I', CURRENT_USER);
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'talos_admin_read: % may not grant itself membership; query_paginated '
                'refuses until a superuser runs GRANT talos_admin_read TO %', CURRENT_USER, CURRENT_USER;
        END;
    END IF;
    GRANT USAGE ON SCHEMA public TO talos_admin_read;
    GRANT SELECT ON TABLE
    public._sqlx_migrations,
    public.actor_action_log,
    public.actor_approval_policies,
    public.actor_budget_policies,
    public.actor_memory,
    public.actors,
    public.agent_roles,
    public.atlassian_integrations,
    public.auth_audit_log,
    public.background_task_leases,
    public.capability_bootstrap,
    public.dead_letter_queue,
    public.execution_approval_tokens,
    public.execution_approvals,
    public.execution_cost_rollup,
    public.execution_events,
    public.execution_memory_context,
    public.execution_state,
    public.github_app_installations,
    public.gmail_integration_audit_log,
    public.gmail_integrations,
    public.google_calendar_audit_log,
    public.google_calendar_integrations,
    public.google_cloud_integrations,
    public.google_health_integrations,
    public.integration_credentials,
    public.integration_state,
    public.judge_scores,
    public.llm_usage,
    public.microsoft_365_integrations,
    public.ml_datasets,
    public.ml_disagreements,
    public.ml_examples,
    public.ml_model_versions,
    public.ml_models,
    public.ml_shadow_stats,
    public.module_execution_logs,
    public.module_executions,
    public.module_marketplace,
    public.module_marketplace_stars,
    public.module_update_history,
    public.modules,
    public.oauth_audit_log,
    public.ops_alert_correction_tokens,
    public.ops_alerts,
    public.ops_alerts_self_monitor_cursor,
    public.organization_members,
    public.organizations,
    public.plaid_items,
    public.resource_quotas,
    public.rotated_session_audit,
    public.schema_audit_log,
    public.scratch_sessions,
    public.semantic_execution_cache,
    public.slack_integration_audit_log,
    public.sub_workflow_runs,
    public.system_settings,
    public.user_audit_settings,
    public.user_module_pins,
    public.user_modules,
    public.webhook_dlq,
    public.webhook_request_log,
    public.worker_identities,
    public.worker_provisioning_tokens,
    public.workflow_action_tokens,
    public.workflow_alerts,
    public.workflow_execution_logs,
    public.workflow_executions,
    public.workflow_executions_archive,
    public.workflow_module_refs,
    public.workflow_reuse_events,
    public.workflow_schedules,
    public.workflow_sla_thresholds,
    public.workflow_suspensions,
    public.workflow_versions,
    public.workflows
    TO talos_admin_read;
END$$;
