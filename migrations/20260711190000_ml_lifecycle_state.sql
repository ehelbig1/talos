-- RFC 0011 P2a — managed distillation lifecycle state on models.
--
-- lifecycle_state drives the llm_only → shadow → hybrid → fast_primary
-- state machine (see RFC 0011 §managed lifecycle); policy_json holds the
-- transition policy (accuracy@coverage, per-class recall floors, minimum
-- human corrections per class, auto_advance). ml_examples.source gains
-- 'llm_production' — answers auto-appended by the DISTILL hook from live
-- traffic, distinct from the one-shot 'llm_bootstrap' corpus so eval can
-- weigh recency and provenance separately.
ALTER TABLE ml_models
    ADD COLUMN IF NOT EXISTS lifecycle_state TEXT NOT NULL DEFAULT 'llm_only'
        CHECK (lifecycle_state IN ('llm_only', 'shadow', 'hybrid', 'fast_primary')),
    ADD COLUMN IF NOT EXISTS policy_json JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Widen the source CHECK (constraint recreated; name from CREATE TABLE).
ALTER TABLE ml_examples DROP CONSTRAINT IF EXISTS ml_examples_source_check;
ALTER TABLE ml_examples ADD CONSTRAINT ml_examples_source_check
    CHECK (source IN ('llm_bootstrap', 'correction', 'llm_fallback',
                      'llm_production', 'import', 'synthetic'));
