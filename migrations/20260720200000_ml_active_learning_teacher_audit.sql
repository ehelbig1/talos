-- RFC 0011 R3 — active-learning routing + teacher-vs-gold audit.
--
-- Gray-band active learning reuses the EXISTING ml_disagreements.kind
-- column (20260711230000): served-but-barely predictions insert with
-- kind='low_confidence' (already in the CHECK), distinguishable from
-- shadow abstentions by fast_label IS NOT NULL. No schema change needed
-- on ml_disagreements.
--
-- teacher_audit: the stored result of ml_teacher_audit (LLM teacher run
-- over the model's gold correction slice; teacher-vs-human accuracy +
-- per-class breakdown + timestamp) so the model card can show it.
ALTER TABLE ml_models
    ADD COLUMN IF NOT EXISTS teacher_audit JSONB;

-- Cheap daily-cap / dedup lookups for gray-band routing: today's
-- low_confidence count and pending same-example rows both hit
-- (model_id, kind, created_at) / (model_id, example_key, status) shapes.
-- The existing (model_id, created_at DESC) index covers the cap COUNT
-- well enough at the 500-row per-model cap; add only the dedup index.
CREATE INDEX IF NOT EXISTS idx_ml_disagreements_model_key_pending
    ON ml_disagreements (model_id, example_key) WHERE status = 'pending';
