-- Add opt-in body logging for webhook triggers.
-- Default is TRUE so existing triggers continue logging bodies as before.
ALTER TABLE webhook_triggers
    ADD COLUMN IF NOT EXISTS log_body BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN webhook_triggers.log_body
    IS 'When false, webhook request/response bodies are redacted from webhook_request_log to protect sensitive payloads.';
