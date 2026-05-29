-- RFC 0004 (Tenant = Organization) — M2: org_id columns + backfill + indexes.
--
-- Additive and idempotent. Adds `org_id` (NULLABLE) to every org-scoped
-- owned table, backfills it from each row's owning user's PERSONAL org
-- (M1), and adds a composite index. NO `NOT NULL` and NO RLS yet — the
-- app still runs on `user_id`; M3 supplies org_id on writes + sets NOT
-- NULL, M4 enables RLS alongside the GUC. Reversible (DROP COLUMN).
--
-- Backfill order matters: PARENT tables (workflows, workflow_executions,
-- secrets, actors) are populated first so child tables can read the
-- parent's now-set org_id. A row whose owning user_id is NULL (orphan /
-- system row) keeps org_id NULL — correct for an additive phase.
--
-- Carve-outs (intentionally NOT org-scoped here):
--   * compilation_cache, node_result_cache — content-addressed shared
--     caches (keyed by source/module/input hash), no owner column.
--   * secrets_rotation_log — platform crypto-ops log (key rotation), no
--     per-tenant owner.
--   * webhook_request_log, webhook_processed_events — link to a webhook
--     trigger (trigger_id), not a user; they carry tenant data and will
--     be org-scoped in a focused follow-up (M2b) via the trigger's owner.
-- See RFC 0004 "Owned tables".

-- Reusable: resolve a user's personal org id.
--   (SELECT o.id FROM organizations o WHERE o.owner_id = <uid> AND o.is_personal)

-- ── Group A: tables with a direct user_id ───────────────────────────
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'actors','agent_memory','atlassian_integrations','dead_letter_jobs',
    'gmail_integrations','google_calendar_integrations','idempotency_keys',
    'integration_credentials','integration_state','jobs','mcp_agents',
    'module_executions','module_marketplace_stars','module_update_history',
    'scratch_sessions','slack_integrations','user_module_pins','workflow_alerts',
    'workflow_approval_gates','workflow_executions','workflow_executions_archive',
    'workflow_schedules','workflow_sla_thresholds','workflow_suspensions'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id)', t);
    EXECUTE format(
      'UPDATE %I x SET org_id = (SELECT o.id FROM organizations o WHERE o.owner_id = x.user_id AND o.is_personal) '
      || 'WHERE x.org_id IS NULL AND x.user_id IS NOT NULL', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_org ON %I (org_id, user_id)', t, t);
  END LOOP;
END $$;

-- ── Group B: tables that ALREADY have org_id (backfill NULLs + index) ─
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['workflows','secrets','modules','api_keys'] LOOP
    EXECUTE format(
      'UPDATE %I x SET org_id = (SELECT o.id FROM organizations o WHERE o.owner_id = x.user_id AND o.is_personal) '
      || 'WHERE x.org_id IS NULL AND x.user_id IS NOT NULL', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_org ON %I (org_id, user_id)', t, t);
  END LOOP;
END $$;

-- ── Group C1: actor_* children → via actors.org_id ──────────────────
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'actor_action_log','actor_approval_policies','actor_budget_policies','actor_memory'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id)', t);
    EXECUTE format(
      'UPDATE %I x SET org_id = (SELECT a.org_id FROM actors a WHERE a.id = x.actor_id) WHERE x.org_id IS NULL', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_org ON %I (org_id)', t, t);
  END LOOP;
END $$;

-- ── Group C2: workflow_* children → via workflows.org_id ────────────
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['workflow_nodes','workflow_versions','semantic_execution_cache'] LOOP
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id)', t);
    EXECUTE format(
      'UPDATE %I x SET org_id = (SELECT w.org_id FROM workflows w WHERE w.id = x.workflow_id) WHERE x.org_id IS NULL', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_org ON %I (org_id)', t, t);
  END LOOP;
END $$;

-- ── Group C3: execution_* children → via workflow_executions.org_id ─
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['execution_events','execution_state','execution_approvals','execution_cost_rollup'] LOOP
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id)', t);
    EXECUTE format(
      'UPDATE %I x SET org_id = (SELECT we.org_id FROM workflow_executions we WHERE we.id = x.execution_id) WHERE x.org_id IS NULL', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_org ON %I (org_id)', t, t);
  END LOOP;
END $$;

-- ── Group C4: secret_audit_log → via secrets.org_id ─────────────────
ALTER TABLE secret_audit_log ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
UPDATE secret_audit_log x
   SET org_id = (SELECT s.org_id FROM secrets s WHERE s.id = x.secret_id)
 WHERE x.org_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_secret_audit_log_org ON secret_audit_log (org_id);
