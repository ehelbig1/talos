-- Security review 2026-07-19 (P5): extend row-level tenant isolation to the
-- remaining org-scoped tenant tables. RLS previously covered only ~12 tables
-- (actors, workflows, secrets, workflow_executions, scratch_sessions,
-- user_module_pins, the six ml_* tables); the highest-value tenant tables the
-- DB-sandbox (P1) and pre-2FA (P3) surfaces touch had NO policy, so their
-- isolation rested entirely on app-layer query scoping with no backstop.
--
-- Every table below already carries an `org_id` column (added in
-- 20260529130000_org_id_columns.sql / 20260529150000_org_id_webhooks.sql), so
-- this migration keys tenant isolation purely on org membership — the same
-- shape as the workflows/secrets/actors policies.
--
-- ROLLOUT-SAFE BY CONSTRUCTION (identical philosophy to the existing RLS
-- migrations):
--   * ENABLE + FORCE, but superusers still bypass RLS entirely — so on the
--     default in-cluster deploy (controller connects as a superuser,
--     TALOS_RLS_SET_ROLE off) these policies are a complete no-op.
--   * The USING/ WITH CHECK clauses are "context-GUC unset -> permit". Engine,
--     signed-NATS-RPC, and any un-wired path set no org GUC, so their
--     reads/writes are permitted unchanged. Enforcement only ever RESTRICTS a
--     row when the caller HAS set org context (the tenant-scoped tx paths).
--   * `org_id IS NULL` rows (org-less / personal / system) are always permitted.
-- Net: takes effect only once an operator runs the controller as the
-- non-superuser `talos_app` role (TALOS_RLS_SET_ROLE=1). VALIDATE under
-- enforcement as part of that enablement, exactly like
-- 20260602120000_rls_with_check_write_isolation.sql.
--
-- READ GUC:  app.current_org_ids (membership set, set by the read scope)
-- WRITE GUC: app.current_org_id  (single active org, set by begin_org_scoped)

DO $$
DECLARE
    t text;
    policy_name text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'actor_memory',
        'integration_credentials',
        'integration_state',
        'slack_integrations',
        'gmail_integrations',
        'google_calendar_integrations',
        'atlassian_integrations',
        'modules',
        'module_executions',
        'webhook_triggers',
        'workflow_schedules',
        'workflow_approval_gates',
        'workflow_suspensions',
        'secret_audit_log'
    ] LOOP
        -- Defensive: skip any table not present in this deployment.
        IF to_regclass(t) IS NULL THEN
            CONTINUE;
        END IF;

        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);

        policy_name := t || '_tenant_isolation';
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', policy_name, t);
        EXECUTE format(
            'CREATE POLICY %I ON %I'
            || ' USING ('
            || '   NULLIF(current_setting(''app.current_org_ids'', true), '''') IS NULL'
            || '   OR org_id IS NULL'
            || '   OR org_id = ANY(string_to_array(NULLIF(current_setting(''app.current_org_ids'', true), ''''), '','')::uuid[])'
            || ' )'
            || ' WITH CHECK ('
            || '   NULLIF(current_setting(''app.current_org_id'', true), '''') IS NULL'
            || '   OR org_id IS NULL'
            || '   OR org_id = NULLIF(current_setting(''app.current_org_id'', true), '''')::uuid'
            || ' )',
            policy_name, t
        );
    END LOOP;
END $$;
