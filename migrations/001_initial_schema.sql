-- Migration 001: Initial Schema
-- Creates all foundational tables and functions for Talos

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Reusable function for updating updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Workflows table
CREATE TABLE workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    module_uri TEXT NOT NULL,
    graph_json TEXT NOT NULL,
    user_id UUID,  -- FK added later when users table exists
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_workflows_name ON workflows(name);

-- Node templates with configuration schemas
CREATE TABLE node_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    category TEXT NOT NULL,  -- 'http', 'transform', 'llm', 'integration'
    description TEXT,
    config_schema JSONB NOT NULL,
    code_template TEXT NOT NULL,
    precompiled_wasm BYTEA,
    icon TEXT,
    user_id UUID,  -- FK added later
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_templates_category ON node_templates(category);

-- Compiled WASM modules
CREATE TABLE wasm_modules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    content_hash TEXT UNIQUE NOT NULL,
    wasm_bytes BYTEA NOT NULL,
    source_code TEXT,
    template_id UUID REFERENCES node_templates(id),
    config JSONB,
    size_bytes INTEGER NOT NULL,
    compiled_at TIMESTAMPTZ DEFAULT NOW(),
    max_fuel BIGINT DEFAULT 1000000,
    max_memory_mb INTEGER DEFAULT 128,
    allowed_hosts TEXT[],
    usage_count INTEGER DEFAULT 0,
    last_used TIMESTAMPTZ,
    user_id UUID  -- FK added later
);

CREATE INDEX idx_modules_hash ON wasm_modules(content_hash);
CREATE INDEX idx_modules_template ON wasm_modules(template_id);

-- Workflow nodes
CREATE TABLE workflow_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID REFERENCES workflows(id) ON DELETE CASCADE,
    module_id UUID REFERENCES wasm_modules(id),
    position_x FLOAT NOT NULL,
    position_y FLOAT NOT NULL,
    config JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_workflow_nodes_workflow ON workflow_nodes(workflow_id);

-- Compilation cache
CREATE TABLE compilation_cache (
    source_hash TEXT PRIMARY KEY,
    module_id UUID REFERENCES wasm_modules(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_compilation_cache_created ON compilation_cache(created_at);

-- ============================================================================
-- SECRETS & WEBHOOKS
-- ============================================================================

-- Encryption keys for secrets
CREATE TABLE encryption_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    encrypted_key BYTEA NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_encryption_keys_active ON encryption_keys(active) WHERE active = true;

-- Secrets storage
CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    key_path TEXT UNIQUE NOT NULL,
    description TEXT,
    encrypted_value BYTEA NOT NULL,
    encryption_key_id UUID NOT NULL REFERENCES encryption_keys(id),
    allowed_modules UUID[],
    created_by UUID,  -- FK added later
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ,
    access_count INTEGER DEFAULT 0,
    user_id UUID  -- FK added later
);

CREATE INDEX idx_secrets_key_path ON secrets(key_path);
CREATE INDEX idx_secrets_created_by ON secrets(created_by);

-- Secret audit log
CREATE TABLE secret_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id UUID REFERENCES secrets(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id UUID,
    module_id UUID,
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    ip_address TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_secret_audit_secret_id ON secret_audit_log(secret_id);
CREATE INDEX idx_secret_audit_timestamp ON secret_audit_log(timestamp DESC);

-- Webhook listeners
CREATE TABLE webhook_listeners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    module_id UUID REFERENCES wasm_modules(id) ON DELETE CASCADE,
    verification_token TEXT NOT NULL,
    signing_secret TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    max_requests_per_minute INTEGER NOT NULL DEFAULT 60,
    trigger_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    user_id UUID  -- FK added later
);

CREATE INDEX idx_webhook_listeners_module_id ON webhook_listeners(module_id);
CREATE INDEX idx_webhook_listeners_enabled ON webhook_listeners(enabled) WHERE enabled = true;

-- Webhook request log
CREATE TABLE webhook_request_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    listener_id UUID REFERENCES webhook_listeners(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    headers JSONB,
    body TEXT,
    source_ip TEXT,
    user_agent TEXT,
    response_status INTEGER,
    response_time_ms INTEGER,
    success BOOLEAN,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_webhook_request_log_listener_id ON webhook_request_log(listener_id);
CREATE INDEX idx_webhook_request_log_created_at ON webhook_request_log(created_at DESC);

-- Triggers for updated_at
CREATE TRIGGER update_workflows_updated_at
    BEFORE UPDATE ON workflows
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_secrets_updated_at
    BEFORE UPDATE ON secrets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_webhook_listeners_updated_at
    BEFORE UPDATE ON webhook_listeners
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
