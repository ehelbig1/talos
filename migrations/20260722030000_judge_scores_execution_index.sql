-- Adaptive per-actor memory ranking — Phase 1 follow-up index.
--
-- The labeled-example query `fetch_rank_training_examples` drives from
-- `execution_memory_context` (up to 50k rows) and for each runs a
-- `LEFT JOIN LATERAL (SELECT score, passed FROM judge_scores
--  WHERE execution_id = emc.execution_id ORDER BY created_at DESC LIMIT 1)`.
-- `judge_scores` was created with only `(workflow_id, created_at DESC)`, so
-- each lateral would scan judge_scores by execution_id — O(rows × |judge_scores|).
-- This index makes the outcome-label lookup an index seek + LIMIT 1.
--
-- Separate migration because `20260721230000_judge_scores.sql` is already
-- applied (never edit an applied migration). Idempotent, no CONCURRENTLY.
CREATE INDEX IF NOT EXISTS idx_judge_scores_execution
    ON judge_scores (execution_id, created_at DESC);
