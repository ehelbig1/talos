-- Migration: Add webhook dead-letter queue table
-- Persists inbound webhook payloads that were dropped by circuit breaker or rate limiter
-- so they can be replayed later. Payload is DLP-scrubbed before storage.

CREATE TABLE IF NOT EXISTS webhook_dlq (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger_id   UUID        REFERENCES webhook_triggers(id) ON DELETE SET NULL,
    source_ip    INET,
    drop_reason  TEXT        NOT NULL, -- 'circuit_breaker' | 'rate_limit' | 'sig_invalid' | 'disabled'
    headers      JSONB,
    payload      JSONB,      -- DLP-scrubbed before storage
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    replayed_at  TIMESTAMPTZ,
    replayed_by  UUID        REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_webhook_dlq_pending ON webhook_dlq(created_at) WHERE replayed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_dlq_trigger ON webhook_dlq(trigger_id, created_at DESC);
