-- Migration 20260322000000: Add workflow_id to webhook_triggers
--
-- This allows webhooks to trigger entire workflows instead of just standalone modules.

ALTER TABLE webhook_triggers ADD COLUMN workflow_id UUID REFERENCES workflows(id) ON DELETE CASCADE;

-- Add index for performance when looking up triggers by workflow
CREATE INDEX IF NOT EXISTS idx_webhook_triggers_workflow_id ON webhook_triggers(workflow_id);

-- Update the comment to reflect the new capability
COMMENT ON TABLE webhook_triggers IS 'Active HTTP trigger configurations: each row maps an inbound webhook URL to either a WASM module or a Workflow execution';

-- Self-validate
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'webhook_triggers' AND column_name = 'workflow_id'
    ) THEN
        RAISE EXCEPTION 'Migration 20260322000000 failed: workflow_id column not found in webhook_triggers';
    END IF;
END $$;
