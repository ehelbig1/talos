-- Add approval gate for AI-generated sandbox templates.
-- Sandboxes created via MCP compile_custom_sandbox start as unapproved in
-- production so that a human administrator can review the generated code
-- before it becomes callable by agents.

ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS is_approved BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS created_by_agent_id UUID;

-- Existing templates are considered approved.
-- Only new sandboxes will default to unapproved in production.

-- Index for fast lookup of unapproved sandboxes awaiting review.
CREATE INDEX IF NOT EXISTS idx_node_templates_pending_review
    ON node_templates(is_approved, category)
    WHERE is_approved = false;
