-- Add index for webhook triggers to optimize lookups during webhook processing
CREATE INDEX IF NOT EXISTS idx_webhook_triggers_lookup ON webhook_triggers(id) WHERE enabled = true;
