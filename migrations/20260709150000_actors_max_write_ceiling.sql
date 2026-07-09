-- Per-actor WRITE CEILING — a default-deny gate on data-mutating operations,
-- mirroring `actors.max_llm_tier` (the LLM data-egress ceiling).
--
--   'readonly' = the actor's jobs may only READ. Every data-mutating host
--                surface (actor-memory writes, DB DML, non-GET HTTP, webhook /
--                email / messaging / object-storage / integration-state writes,
--                GraphQL execute) is refused in the worker.
--   'write'    = mutation permitted (subject to the module's capability grant).
--
-- Enforcement is worker-side and gated by `TALOS_WRITE_CEILING_ENFORCED`
-- (default off) so this ships inert; operators flip enforcement on deliberately.
-- The value travels HMAC-bound in JobRequest/PipelineJobRequest so it can't be
-- upgraded on the wire.
ALTER TABLE actors
    ADD COLUMN IF NOT EXISTS max_write_ceiling TEXT NOT NULL DEFAULT 'readonly'
    CHECK (max_write_ceiling IN ('readonly', 'write'));

-- allow-non-idempotent: one-shot grandfather of pre-existing actors. Guarded by
-- the column DEFAULT above (new actors get 'readonly'); this UPDATE runs exactly
-- once at first-apply to flip the actors that existed BEFORE this migration to
-- 'write' so nothing currently running (agent-memory writes, integrations, the
-- inbox organizer) breaks. Re-running would be wrong (it would reset later
-- readonly actors to write), but sqlx applies each migration exactly once.
UPDATE actors SET max_write_ceiling = 'write';
