-- Track when get_readiness_breakdown last computed the score for each workflow.
-- Populated by the readiness score write-back in the MCP handler.
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS readiness_scored_at TIMESTAMPTZ;
