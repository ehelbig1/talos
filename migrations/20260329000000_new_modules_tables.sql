-- Add jobs table for background job queue
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payload JSONB NOT NULL,
    priority INT NOT NULL DEFAULT 2,
    status TEXT NOT NULL DEFAULT 'pending',
    user_id UUID NOT NULL REFERENCES users(id),
    organization_id UUID REFERENCES organizations(id),
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 3,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    worker_id TEXT
);

CREATE INDEX idx_jobs_status_scheduled ON jobs(status, scheduled_at);
CREATE INDEX idx_jobs_user_id ON jobs(user_id);
CREATE INDEX idx_jobs_priority ON jobs(priority DESC);

-- Add dead_letter_jobs table
CREATE TABLE IF NOT EXISTS dead_letter_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_job_id UUID NOT NULL REFERENCES jobs(id),
    payload JSONB NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    error_message TEXT NOT NULL,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dead_letter_jobs_original ON dead_letter_jobs(original_job_id);

-- Add feature_flags table
CREATE TABLE IF NOT EXISTS feature_flags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id)
);

CREATE INDEX idx_feature_flags_name ON feature_flags(name);

-- Add idempotency_keys table
CREATE TABLE IF NOT EXISTS idempotency_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key TEXT NOT NULL UNIQUE,
    request_hash TEXT NOT NULL,
    response_body TEXT,
    status_code INT NOT NULL,
    user_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_idempotency_keys_key ON idempotency_keys(key);
CREATE INDEX idx_idempotency_keys_expires ON idempotency_keys(expires_at);

-- Add tenant_quotas table for multi-tenancy
CREATE TABLE IF NOT EXISTS tenant_quotas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations(id),
    max_workflows INT NOT NULL DEFAULT 100,
    max_executions INT NOT NULL DEFAULT 50,
    max_secrets INT NOT NULL DEFAULT 100,
    api_rate_limit INT NOT NULL DEFAULT 1000,
    max_fuel_per_execution BIGINT NOT NULL DEFAULT 100000,
    max_memory_per_execution INT NOT NULL DEFAULT 256,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_tenant_quotas_tenant ON tenant_quotas(tenant_id);

-- Add secrets_rotation_log table
CREATE TABLE IF NOT EXISTS secrets_rotation_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_type TEXT NOT NULL,
    key_id TEXT NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_by UUID REFERENCES users(id),
    expires_at TIMESTAMPTZ,
    reason TEXT
);

CREATE INDEX idx_secrets_rotation_key_type ON secrets_rotation_log(key_type, rotated_at);

-- Add circuit_breaker_metrics table
CREATE TABLE IF NOT EXISTS circuit_breaker_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name TEXT NOT NULL,
    state TEXT NOT NULL,
    failure_count INT NOT NULL DEFAULT 0,
    success_count INT NOT NULL DEFAULT 0,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_circuit_breaker_service ON circuit_breaker_metrics(service_name, recorded_at);

-- Add webhook_processed_events for deduplication
CREATE TABLE IF NOT EXISTS webhook_processed_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger_id UUID NOT NULL,
    event_id TEXT NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(trigger_id, event_id)
);

CREATE INDEX idx_webhook_events_trigger ON webhook_processed_events(trigger_id, event_id);

-- Self-validating check
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'jobs') THEN
        RAISE EXCEPTION 'Migration failed: jobs table not created';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'feature_flags') THEN
        RAISE EXCEPTION 'Migration failed: feature_flags table not created';
    END IF;
END $$;
