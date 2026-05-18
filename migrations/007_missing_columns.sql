-- Migration 007: Add Missing Columns
-- Add columns that were in the code but missing from migrations

-- Webhook listener additions
ALTER TABLE webhook_listeners
    ADD COLUMN IF NOT EXISTS allowed_ips TEXT[],
    ADD COLUMN IF NOT EXISTS auto_respond BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS queue_events BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS avg_response_ms INTEGER;

-- Secret additions
ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS nonce BYTEA,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Secret audit log additions
ALTER TABLE secret_audit_log
    ADD COLUMN IF NOT EXISTS error_message TEXT;

-- Secrets: Add owner_user_id
ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Webhook request log: Add status_code, response_body, and wasm_execution_ms
ALTER TABLE webhook_request_log
    ADD COLUMN IF NOT EXISTS status_code INTEGER,
    ADD COLUMN IF NOT EXISTS response_body TEXT,
    ADD COLUMN IF NOT EXISTS wasm_execution_ms INTEGER;
