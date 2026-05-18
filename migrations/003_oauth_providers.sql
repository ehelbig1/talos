-- Migration 003: OAuth Providers
-- Google, Okta, Snyk OAuth authentication

-- OAuth linked accounts
CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT,
    picture_url TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    UNIQUE(provider, provider_user_id),
    UNIQUE(user_id, provider)
);

CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);
CREATE INDEX idx_oauth_accounts_provider_user ON oauth_accounts(provider, provider_user_id);
CREATE INDEX idx_oauth_accounts_email ON oauth_accounts(email);

-- OAuth state tokens for CSRF protection
CREATE TABLE oauth_state_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state_token TEXT UNIQUE NOT NULL,
    provider TEXT NOT NULL,
    used BOOLEAN DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '10 minutes'),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_oauth_state_tokens_state ON oauth_state_tokens(state_token);
CREATE INDEX idx_oauth_state_tokens_expires ON oauth_state_tokens(expires_at);

-- OAuth audit log
CREATE TABLE oauth_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    provider TEXT NOT NULL,
    event_type TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_oauth_audit_log_user_id ON oauth_audit_log(user_id);
CREATE INDEX idx_oauth_audit_log_provider ON oauth_audit_log(provider);
CREATE INDEX idx_oauth_audit_log_created_at ON oauth_audit_log(created_at DESC);
