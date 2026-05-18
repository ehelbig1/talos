-- Migration 029: User Audit Settings for OTLP Streaming

CREATE TABLE user_audit_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    streaming_enabled BOOLEAN NOT NULL DEFAULT false,
    otlp_endpoint TEXT,
    otlp_protocol TEXT CHECK (otlp_protocol IN ('grpc', 'http')),
    auth_headers_encrypted BYTEA,
    auth_headers_nonce BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_user_audit_settings_updated_at
    BEFORE UPDATE ON user_audit_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
