-- Per-actor LLM data-egress tier ceiling.
--
-- Sensitive actors (medical, financial, relationship context) need a
-- way to fail-closed against accidentally sending payloads to external
-- LLM providers (Anthropic / OpenAI / Gemini). This column gates which
-- tier a job dispatched on behalf of the actor may reach:
--
--   tier1 = Ollama only — payloads stay on-host
--   tier2 = anything (current behavior; default for backward compat)
--
-- Worker-side enforcement: when the JobRequest carries `tier1`, the
-- worker's `get_llm_api_key` refuses to resolve keys for any external
-- provider and the job fails closed.
--
-- Default `tier2` matches the pre-feature behavior so existing
-- workflows aren't disrupted. Operators flip sensitive actors via
-- `set_actor_llm_tier_ceiling` MCP tool.

ALTER TABLE actors
    ADD COLUMN max_llm_tier TEXT NOT NULL DEFAULT 'tier2'
    CHECK (max_llm_tier IN ('tier1', 'tier2'));

COMMENT ON COLUMN actors.max_llm_tier IS
    'LLM data-egress ceiling: tier1 = Ollama only (payloads stay on-host), tier2 = external providers allowed (Anthropic/OpenAI/Gemini). Worker enforces by refusing to resolve external-provider vault keys when tier1.';
