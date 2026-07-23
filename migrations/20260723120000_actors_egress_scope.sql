-- Per-actor network-egress scope — a security axis INDEPENDENT of
-- `max_llm_tier`, decoupling the blanket "no public egress" SSRF gate from
-- the LLM-provider gate.
--
-- Historically `max_llm_tier = 'tier1'` drove BOTH "no external LLM" AND
-- "no public network egress at all". That conflation meant an actor that
-- only needs its LLM kept local (e.g. the personal-assistant, whose LLM
-- nodes are Ollama-pinned) also lost access to legitimate public APIs it
-- must reach — e.g. reading Gmail over HTTPS. This column lets an actor be
-- `max_llm_tier = 'tier1'` (LLM hard-gated local) AND `egress_scope =
-- 'public'` (can reach declared allowed_hosts like gmail.googleapis.com).
--
-- NULLABLE OVERRIDE semantics (backward-compatible, no backfill):
--   NULL     -> fall back to the tier-derived default (tier1 => local,
--               tier2 => public). Every existing actor is NULL, so the
--               blanket-egress behavior is byte-identical until an operator
--               sets an explicit scope. This is why there is deliberately
--               NO backfill UPDATE here.
--   'local'  -> deny all public egress (classic air-gapped posture),
--               regardless of max_llm_tier.
--   'public' -> permit public egress (subject to per-module allowed_hosts +
--               SSRF filtering), regardless of max_llm_tier. The
--               LLM-provider deny (keyed to max_llm_tier) still applies.
--
-- Enforcement: overrides ONLY the worker-side `local_egress_only` SSRF gate.
-- The LLM-provider name deny, the raw wasi:sockets grant, and the
-- public-IP-literal deny all remain keyed to max_llm_tier (fail-closed).

ALTER TABLE actors
    ADD COLUMN IF NOT EXISTS egress_scope text DEFAULT NULL
    CONSTRAINT actors_egress_scope_check
        CHECK (egress_scope IS NULL OR egress_scope IN ('local', 'public'));
