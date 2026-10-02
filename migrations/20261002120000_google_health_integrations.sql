-- Google Health connection (Pixel Watch / Fitbit readings via the Google
-- Health API).
--
-- Metadata only, the same shape as google_cloud_integrations without a tier.
-- Tokens live in the unified integration_credentials table (via
-- OAuthCredentialService) at vault path
-- oauth/google_health/{user_id}/{provider_key}/access_token.
--
-- provider_key is a stable UUID derived from the connected Google account id
-- (Sha256(google_account_id)[..16]); reconnecting the same account UPDATEs
-- (UNIQUE(user_id, provider_key)) rather than duplicating. account_email is a
-- display-only label for the settings page.
--
-- No separate index on user_id: UNIQUE(user_id, provider_key) already serves
-- a lookup by user (a non-unique index that is a leading prefix of a sibling
-- is refused by the index-hygiene test).
--
-- No RLS policy, like google_cloud_integrations: every reader names the user
-- (WHERE user_id = $N) on the service pool, and no tenant-scoped connection
-- touches the table.

CREATE TABLE IF NOT EXISTS google_health_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_key UUID NOT NULL,
    account_email TEXT,
    token_expires_at TIMESTAMPTZ,
    scope TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, provider_key)
);

CREATE OR REPLACE FUNCTION update_google_health_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS google_health_integrations_updated_at ON google_health_integrations;
CREATE TRIGGER google_health_integrations_updated_at
    BEFORE UPDATE ON google_health_integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_google_health_integrations_updated_at();
