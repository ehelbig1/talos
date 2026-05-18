-- Migration 004: Slack Integration
-- Slack workspace connections and OAuth tokens

CREATE TABLE slack_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id VARCHAR(255) NOT NULL,
    team_name VARCHAR(255) NOT NULL,
    team_domain VARCHAR(255),
    bot_token TEXT NOT NULL,
    bot_user_id VARCHAR(255),
    access_token TEXT,
    app_id VARCHAR(255),
    scope TEXT,
    verification_token VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    UNIQUE(user_id, team_id)
);

CREATE INDEX idx_slack_integrations_user_id ON slack_integrations(user_id);
CREATE INDEX idx_slack_integrations_team_id ON slack_integrations(team_id);
CREATE INDEX idx_slack_integrations_active ON slack_integrations(is_active) WHERE is_active = TRUE;

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_slack_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER slack_integrations_updated_at
    BEFORE UPDATE ON slack_integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_slack_integrations_updated_at();

-- Audit log
CREATE TABLE slack_integration_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID REFERENCES slack_integrations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_slack_audit_integration_id ON slack_integration_audit_log(integration_id);
CREATE INDEX idx_slack_audit_user_id ON slack_integration_audit_log(user_id);
CREATE INDEX idx_slack_audit_created_at ON slack_integration_audit_log(created_at DESC);
