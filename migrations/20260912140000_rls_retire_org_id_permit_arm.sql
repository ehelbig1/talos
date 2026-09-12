-- Retire the `org_id IS NULL → permit` arm on the eleven RLS policies whose
-- table never has its `org_id` written.
--
-- RFC 0004's M2 (20260529130000) added `org_id` to every owned table and
-- backfilled it; its M4 policies kept a TRANSITION arm — `OR org_id IS NULL`
-- — so that rows the M3 write-side stamping had not yet reached stayed
-- visible. M3 landed as `set_org_id_from_personal_org` (20260529140000), a
-- BEFORE INSERT trigger deliberately scoped to FOUR definition tables
-- (actors, secrets, modules, webhook_triggers). For every other table the
-- transition never ended. Measured on the dev database 2026-09-12:
--
--   module_executions        56 633 rows   org_id NULL on 56 633   user_id set on 56 633
--   secret_audit_log         22 593        NULL on 22 593
--   workflow_schedules           18        NULL on 18              user_id set on 18
--   integration_credentials       7        NULL on 7               user_id set on 7
--   gmail / gcal / integration_state  2 each, NULL on all         user_id set
--   atlassian / slack / suspensions / approval_gates  0 rows
--
-- With the fleet on TALOS_RLS_SET_ROLE=true, a scoped transaction that reads
-- one of these tables runs as talos_app and the policy IS evaluated — and
-- its permit arm admits every row to every tenant. `workflow_schedules` has
-- FIVE readers on scoped connections (`get_schedule_for_accessor_on_conn`,
-- `get_schedule_for_update_on_conn`, `upsert/update/delete_schedule_on_conn`),
-- so for that table the backstop the policy was meant to be has been a
-- pass-through since May. The other ten have no scoped reader today (their
-- reads run on the bare superuser pool, where RLS is bypassed), but they
-- REPORT as RLS-protected — `relrowsecurity = t`, a named tenant-isolation
-- policy — while isolating nothing the moment a scoped reader appears.
-- Presence is not function; the same policy names now mean what they say.
--
-- SHAPE. The tenant key is the one that IS written: `user_id` (populated on
-- every row of every table here that has it), with the org arm kept for a
-- future explicit stamp, and a PARENT-derived arm where the table hangs off
-- one (`workflow_schedules` → workflows, `module_executions` /
-- `workflow_suspensions` → workflow_executions, `secret_audit_log` → secrets,
-- the only tenant key that table has). Under talos_app the parent's own
-- policy filters the EXISTS, so org sharing follows the parent with no
-- second copy of the membership arithmetic (20260912130000's shape). The
-- unset→permit clause is kept and keyed on `app.current_user_id`, as
-- `workflows_tenant_isolation` keys it: `begin_user_scoped` /
-- `begin_tenant_read_scoped` set it, and the engine / analytics / sweep
-- paths that set no GUC keep working. WITH CHECK is the owner (or parent)
-- arm without the org arm, mirroring 20260602120000. FORCE stays.
--
-- Deliberately NOT done: stamping `org_id` on these tables' writers, or
-- widening the autostamp trigger to them. The M3 migration's own reasoning
-- (per-insert subquery cost on high-write operational tables) still holds,
-- and a policy keyed on a column that is written is worth more than a
-- column that might one day be.
--
-- Proved before it was written on a full copy of the dev database: under
-- talos_app the owning user sees 18 / 56 633 / 7 (all rows — one user owns
-- this fleet) and a stranger 0 / 0 / 0; the scoped scheduler statements
-- keep their index plans.

ALTER TABLE integration_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS integration_credentials_tenant_isolation ON integration_credentials;
CREATE POLICY integration_credentials_tenant_isolation ON integration_credentials
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER TABLE integration_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS integration_state_tenant_isolation ON integration_state;
CREATE POLICY integration_state_tenant_isolation ON integration_state
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER TABLE gmail_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE gmail_integrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS gmail_integrations_tenant_isolation ON gmail_integrations;
CREATE POLICY gmail_integrations_tenant_isolation ON gmail_integrations
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER TABLE google_calendar_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE google_calendar_integrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS google_calendar_integrations_tenant_isolation ON google_calendar_integrations;
CREATE POLICY google_calendar_integrations_tenant_isolation ON google_calendar_integrations
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER TABLE atlassian_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE atlassian_integrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS atlassian_integrations_tenant_isolation ON atlassian_integrations;
CREATE POLICY atlassian_integrations_tenant_isolation ON atlassian_integrations
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER TABLE slack_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE slack_integrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS slack_integrations_tenant_isolation ON slack_integrations;
CREATE POLICY slack_integrations_tenant_isolation ON slack_integrations
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER TABLE workflow_approval_gates ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_approval_gates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workflow_approval_gates_tenant_isolation ON workflow_approval_gates;
CREATE POLICY workflow_approval_gates_tenant_isolation ON workflow_approval_gates
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[])
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER TABLE workflow_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_schedules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workflow_schedules_tenant_isolation ON workflow_schedules;
CREATE POLICY workflow_schedules_tenant_isolation ON workflow_schedules
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR EXISTS (SELECT 1 FROM workflows w WHERE w.id = workflow_schedules.workflow_id)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR EXISTS (SELECT 1 FROM workflows w WHERE w.id = workflow_schedules.workflow_id)
);

ALTER TABLE workflow_suspensions ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_suspensions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workflow_suspensions_tenant_isolation ON workflow_suspensions;
CREATE POLICY workflow_suspensions_tenant_isolation ON workflow_suspensions
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR EXISTS (SELECT 1 FROM workflow_executions we WHERE we.id = workflow_suspensions.execution_id)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

ALTER TABLE module_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE module_executions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS module_executions_tenant_isolation ON module_executions;
CREATE POLICY module_executions_tenant_isolation ON module_executions
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR EXISTS (SELECT 1 FROM workflow_executions we WHERE we.id = module_executions.workflow_execution_id)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR EXISTS (SELECT 1 FROM workflow_executions we WHERE we.id = module_executions.workflow_execution_id)
);

ALTER TABLE secret_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_audit_log_tenant_isolation ON secret_audit_log;
CREATE POLICY secret_audit_log_tenant_isolation ON secret_audit_log
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM secrets s WHERE s.id = secret_audit_log.secret_id)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM secrets s WHERE s.id = secret_audit_log.secret_id)
);
