-- Rename agent → actor throughout the schema.
-- This is a surgical rename: behaviour, data, and constraints are unchanged.
-- All references (FKs, indexes, triggers) are updated atomically.

-- ─── 1. Rename core tables ──────────────────────────────────────────────────

ALTER TABLE IF EXISTS agents                 RENAME TO actors;
ALTER TABLE IF EXISTS agent_budget_policies  RENAME TO actor_budget_policies;
ALTER TABLE IF EXISTS agent_approval_policies RENAME TO actor_approval_policies;
ALTER TABLE IF EXISTS agent_action_log       RENAME TO actor_action_log;
ALTER TABLE IF EXISTS agent_runtime_memory   RENAME TO actor_memory;

-- ─── 2. Rename primary-key columns on child tables ──────────────────────────

-- actor_budget_policies: agent_id → actor_id (PK + FK)
ALTER TABLE actor_budget_policies
    RENAME COLUMN agent_id TO actor_id;

-- actor_approval_policies: agent_id → actor_id
ALTER TABLE actor_approval_policies
    RENAME COLUMN agent_id TO actor_id;

-- actor_action_log: agent_id → actor_id
ALTER TABLE actor_action_log
    RENAME COLUMN agent_id TO actor_id;

-- actor_memory: agent_id → actor_id + update UNIQUE constraint
ALTER TABLE actor_memory
    RENAME COLUMN agent_id TO actor_id;

-- ─── 3. Rename FK columns everywhere ───────────────────────────────────────

-- node_templates.created_by_agent_id → created_by_actor_id (column may not exist in all deployments)
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'node_templates' AND column_name = 'created_by_agent_id'
    ) THEN
        ALTER TABLE node_templates RENAME COLUMN created_by_agent_id TO created_by_actor_id;
    END IF;
END $$;



-- workflows.agent_id → actor_id
ALTER TABLE workflows
    RENAME COLUMN agent_id TO actor_id;

-- workflow_executions.agent_id → actor_id
ALTER TABLE workflow_executions
    RENAME COLUMN agent_id TO actor_id;

-- workflow_executions_archive.agent_id → actor_id (added in 20260323000100; column may not exist)
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'workflow_executions_archive' AND column_name = 'agent_id'
    ) THEN
        ALTER TABLE workflow_executions_archive RENAME COLUMN agent_id TO actor_id;
    END IF;
END $$;

-- ─── 4. Rename indexes ──────────────────────────────────────────────────────

ALTER INDEX IF EXISTS idx_agents_user_id         RENAME TO idx_actors_user_id;
ALTER INDEX IF EXISTS idx_agents_active          RENAME TO idx_actors_active;
ALTER INDEX IF EXISTS idx_agents_user_name       RENAME TO idx_actors_user_name;
ALTER INDEX IF EXISTS idx_agent_approval_policies_agent RENAME TO idx_actor_approval_policies_actor;
ALTER INDEX IF EXISTS idx_agent_action_log_agent_ts    RENAME TO idx_actor_action_log_actor_ts;
ALTER INDEX IF EXISTS idx_agent_runtime_memory_agent   RENAME TO idx_actor_memory_actor;
ALTER INDEX IF EXISTS idx_agent_runtime_memory_expires RENAME TO idx_actor_memory_expires;
ALTER INDEX IF EXISTS idx_workflows_agent_id     RENAME TO idx_workflows_actor_id;
ALTER INDEX IF EXISTS idx_wf_executions_agent_id RENAME TO idx_wf_executions_actor_id;

-- ─── 5. Rename sequences / triggers where names bake in "agent" ─────────────
-- (Postgres auto-names update triggers; none were explicitly named "agent_*"
--  so no trigger renames are needed here.)

-- ─── 6. Update archived status check constraint on actors ───────────────────
-- The 20260322000001 migration added 'archived' to agents.status;
-- after the table rename the constraint name still bakes in "agents" — rename it.
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'agents_status_check'
    ) THEN
        ALTER TABLE actors RENAME CONSTRAINT agents_status_check TO actors_status_check;
    END IF;
END $$;

-- The UNIQUE constraint from idx_agents_user_name is index-based, already renamed above.

DO $$ BEGIN
    RAISE NOTICE 'agents→actors rename complete: tables, columns, indexes';
END $$;
