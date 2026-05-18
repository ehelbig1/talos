-- Synchronous webhook response mode.
-- When enabled, the webhook handler holds the HTTP connection open and returns
-- the workflow output as the response body (within sync_timeout_secs).

ALTER TABLE webhook_triggers
    ADD COLUMN IF NOT EXISTS sync_response BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS sync_timeout_secs INT NOT NULL DEFAULT 30;

COMMENT ON COLUMN webhook_triggers.sync_response IS 'When true, webhook handler waits for workflow completion and returns output in HTTP response body.';
COMMENT ON COLUMN webhook_triggers.sync_timeout_secs IS 'Maximum seconds to wait for workflow completion in sync mode. Returns 504 on timeout.';
