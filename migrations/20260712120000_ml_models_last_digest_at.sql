-- RFC 0011 — disagreement-digest fair-rotation cursor.
--
-- The digest task visits digest-configured models least-recently-visited
-- first and stamps this on every visit, so a fleet with more
-- digest-configured models than one tick's scan cap still cycles through
-- all of them instead of permanently starving the tail (the same
-- rotation the policy evaluator uses via last_policy_eval_at).
ALTER TABLE ml_models
    ADD COLUMN IF NOT EXISTS last_digest_at TIMESTAMPTZ;
