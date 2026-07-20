-- AI-architecture review R2: per-actor LLM token accounting.
--
-- Every LLM call's provider-reported token usage is recorded here, aggregated
-- per (execution, provider, model). Worker-observed usage travels inside the
-- SIGNED JobResult/PipelineJobResult (workers are credential-free and DB-free);
-- the controller inserts rows at the result-ingest chokepoints, attributing
-- actor_id/user_id from ITS OWN execution records — never from worker claims.
-- Controller-side LLM calls (judges, teacher legs, workflow creation) record
-- through the same table via a global usage sink.
--
-- actor_id is nullable: controller-side scaffolding calls (e.g. workflow
-- creation for a user) can lack an owning actor; they record with the user's
-- id and a NULL actor. Worker-execution rows always carry the actor.
-- user_id is nullable too: a few controller-side call sites (graph-RAG
-- entity extraction, background maintenance) run under the platform trust
-- boundary with no requesting user; those rows record NULL user_id and are
-- excluded from per-user rollups by construction. Every path that KNOWS the
-- user attributes it (worker rows from the execution record; controller
-- rows via the talos-llm task-local attribution scope).
-- org_id is carried (nullable) for consistency with the tenant-table RLS
-- sweep pattern (20260719120000); org-less/system rows leave it NULL.

CREATE TABLE IF NOT EXISTS llm_usage (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id uuid NULL,
    workflow_id uuid NULL,
    actor_id uuid NULL,
    user_id uuid NULL,
    org_id uuid NULL,
    provider text NOT NULL,
    model text NOT NULL,
    prompt_tokens bigint NOT NULL DEFAULT 0,
    completion_tokens bigint NOT NULL DEFAULT 0,
    calls integer NOT NULL DEFAULT 1,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

-- Budget-window query: SUM(tokens) per actor over a trailing window.
CREATE INDEX IF NOT EXISTS idx_llm_usage_actor_recorded
    ON llm_usage (actor_id, recorded_at);

-- Weekly-report query: per-user usage over a trailing window.
CREATE INDEX IF NOT EXISTS idx_llm_usage_user_recorded
    ON llm_usage (user_id, recorded_at);

-- R2 daily token ceiling: NULL = no ceiling (default). Enforced at trigger
-- authorization alongside max_executions_per_hour, against
-- SUM(prompt_tokens + completion_tokens) over the trailing 24 hours.
ALTER TABLE actor_budget_policies
    ADD COLUMN IF NOT EXISTS max_llm_tokens_per_day bigint NULL;
