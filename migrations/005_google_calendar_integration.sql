-- Migration 005: Google Calendar Integration
-- Google Calendar OAuth and watch channels

CREATE TABLE google_calendar_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    oauth_account_id UUID NOT NULL REFERENCES oauth_accounts(id) ON DELETE CASCADE,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    scope TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, oauth_account_id)
);

CREATE INDEX idx_google_calendar_integrations_user_id ON google_calendar_integrations(user_id);
CREATE INDEX idx_google_calendar_integrations_oauth_account ON google_calendar_integrations(oauth_account_id);
CREATE INDEX idx_google_calendar_integrations_active ON google_calendar_integrations(is_active) WHERE is_active = TRUE;

-- Watch channels for push notifications
CREATE TABLE google_calendar_watch_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID NOT NULL REFERENCES google_calendar_integrations(id) ON DELETE CASCADE,
    calendar_id VARCHAR(255) NOT NULL,
    channel_id VARCHAR(255) NOT NULL UNIQUE,
    resource_id VARCHAR(255) NOT NULL,
    webhook_url TEXT NOT NULL,
    expiration TIMESTAMPTZ NOT NULL,
    sync_token TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_google_calendar_watch_channels_integration_id ON google_calendar_watch_channels(integration_id);
CREATE INDEX idx_google_calendar_watch_channels_calendar_id ON google_calendar_watch_channels(calendar_id);
CREATE INDEX idx_google_calendar_watch_channels_expiration ON google_calendar_watch_channels(expiration) WHERE is_active = TRUE;
CREATE INDEX idx_google_calendar_watch_channels_active ON google_calendar_watch_channels(is_active) WHERE is_active = TRUE;

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_google_calendar_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER google_calendar_integrations_updated_at
    BEFORE UPDATE ON google_calendar_integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_google_calendar_integrations_updated_at();

CREATE OR REPLACE FUNCTION update_google_calendar_watch_channels_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER google_calendar_watch_channels_updated_at
    BEFORE UPDATE ON google_calendar_watch_channels
    FOR EACH ROW
    EXECUTE FUNCTION update_google_calendar_watch_channels_updated_at();

-- Audit log
CREATE TABLE google_calendar_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID REFERENCES google_calendar_integrations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    calendar_id VARCHAR(255),
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_google_calendar_audit_integration_id ON google_calendar_audit_log(integration_id);
CREATE INDEX idx_google_calendar_audit_user_id ON google_calendar_audit_log(user_id);
CREATE INDEX idx_google_calendar_audit_created_at ON google_calendar_audit_log(created_at DESC);
