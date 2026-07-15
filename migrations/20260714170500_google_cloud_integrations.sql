-- Google Cloud Platform integration table.
--
-- Mirrors the gmail_integrations / google_calendar_integrations shape:
-- metadata only. Tokens live exclusively in the unified
-- integration_credentials table (via OAuthCredentialService) at vault
-- path oauth/google_cloud/{user_id}/{provider_key}/access_token.
--
-- provider_key is a stable UUID derived from the connected Google
-- account id (Sha256(google_account_id)[..16]); reconnecting the same
-- account UPDATEs (UNIQUE(user_id, provider_key)) rather than
-- duplicating. account_email is a display-only label for the settings UI.
--
-- Like the gmail/gcal integration tables, this table has no RLS policy
-- (tenancy is enforced in the service layer via WHERE user_id = $N).

CREATE TABLE IF NOT EXISTS google_cloud_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_key UUID NOT NULL,
    account_email TEXT,
    account_name TEXT,
    token_expires_at TIMESTAMPTZ,
    scope TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    UNIQUE (user_id, provider_key)
);

CREATE INDEX IF NOT EXISTS idx_google_cloud_integrations_user_id
    ON google_cloud_integrations (user_id);
CREATE INDEX IF NOT EXISTS idx_google_cloud_integrations_active
    ON google_cloud_integrations (is_active) WHERE is_active = TRUE;

-- updated_at maintenance trigger (mirrors the gcal pattern).
CREATE OR REPLACE FUNCTION update_google_cloud_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS google_cloud_integrations_updated_at ON google_cloud_integrations;
CREATE TRIGGER google_cloud_integrations_updated_at
    BEFORE UPDATE ON google_cloud_integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_google_cloud_integrations_updated_at();
