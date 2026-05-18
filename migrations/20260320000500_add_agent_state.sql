-- Phase 5.1 / 3.3 / 1.1: Agent memory store + agent_id columns on core tables.

-- DB-backed runtime-agent memory (typed, scoped, TTL-aware).
-- NOTE: `agent_memory` is already taken by migration 20260312000500 for workflow-scoped
-- key-value storage. This table serves the NEW autonomous runtime agents introduced in
-- migration 20260320000300, which are a distinct concept — so we use `agent_runtime_memory`.
-- Redis can act as read-through cache in front of hot keys, but the source
-- of truth lives here so memory survives Redis restarts and is auditable.
CREATE TABLE IF NOT EXISTS agent_runtime_memory (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       JSONB NOT NULL,
    -- working:    1-hour TTL, cleared on agent suspend
    -- episodic:   7-day TTL, survives suspension
    -- semantic:   no TTL, requires explicit forget()
    -- scratchpad: execution-scoped (~24h), auto-cleared
    memory_type TEXT NOT NULL DEFAULT 'working'
                    CHECK (memory_type IN ('working', 'episodic', 'semantic', 'scratchpad')),
    expires_at  TIMESTAMPTZ,   -- NULL means no expiry (semantic memories)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, key)
);

CREATE INDEX IF NOT EXISTS idx_agent_runtime_memory_agent
    ON agent_runtime_memory(agent_id);
-- Partial index for TTL cleanup queries (only rows that can expire).
CREATE INDEX IF NOT EXISTS idx_agent_runtime_memory_expires
    ON agent_runtime_memory(expires_at) WHERE expires_at IS NOT NULL;

-- Tag workflows with the owning runtime agent.
-- NULL = human-created workflow (not agent-owned).
ALTER TABLE workflows
    ADD COLUMN IF NOT EXISTS agent_id UUID REFERENCES agents(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_workflows_agent_id
    ON workflows(agent_id) WHERE agent_id IS NOT NULL;

-- Tag executions with the owning runtime agent and a provenance chain
-- for tracing back to the originating LLM decision.
ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS agent_id UUID REFERENCES agents(id) ON DELETE SET NULL;

-- Phase 3.3: Execution provenance for traceability.
-- {
--   "agent_id": "...",
--   "parent_execution_id": "...",
--   "parent_node_id": "...",
--   "trigger_type": "human | schedule | webhook | llm_dispatch | capability_dispatch",
--   "llm_model": "claude-sonnet-4-6",
--   "llm_prompt_hash": "sha256:..."
-- }
ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS provenance JSONB;

CREATE INDEX IF NOT EXISTS idx_wf_executions_agent_id
    ON workflow_executions(agent_id) WHERE agent_id IS NOT NULL;

DO $$ BEGIN RAISE NOTICE 'agent_runtime_memory, workflows.agent_id, workflow_executions.agent_id+provenance ready'; END $$;
