-- Microsoft 365 connection.
--
-- Metadata only. Tokens live in the unified integration_credentials table
-- (via OAuthCredentialService) at vault path
-- oauth/microsoft_365/{user_id}/{provider_key}/access_token.
--
-- provider_key is the provider's stable id for the connected account;
-- reconnecting the same account UPDATEs (UNIQUE(user_id, provider_key))
-- rather than duplicating. account_label is a display-only label for the
-- settings page.
--
-- No separate index on user_id: UNIQUE(user_id, provider_key) already serves
-- a lookup by user (a non-unique index that is a leading prefix of a sibling
-- is refused by the index-hygiene test).
--
-- No RLS policy, like google_health_integrations: every reader names the user
-- (WHERE user_id = $N) on the service pool, and no tenant-scoped connection
-- touches the table. If a tenant-scoped reader is ever added, add the policy
-- with it.

CREATE TABLE IF NOT EXISTS microsoft_365_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL,
    account_label TEXT,
    token_expires_at TIMESTAMPTZ,
    scope TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, provider_key)
);

CREATE OR REPLACE FUNCTION update_microsoft_365_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS microsoft_365_integrations_updated_at ON microsoft_365_integrations;
CREATE TRIGGER microsoft_365_integrations_updated_at
    BEFORE UPDATE ON microsoft_365_integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_microsoft_365_integrations_updated_at();
