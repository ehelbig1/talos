-- Google Calendar (add events) connection.
--
-- Metadata only. Tokens live in the unified integration_credentials table
-- (via OAuthCredentialService) at vault path
-- oauth/google_calendar_write/{user_id}/{provider_key}/access_token.
--
-- This is a SECOND connection to Google Calendar, beside the read-only
-- google_calendar_integrations: it carries the one write scope
-- (calendar.events.owned) and its tokens live in their own vault namespace, so
-- a module granted the read connection cannot name them.
--
-- provider_key is a stable UUID derived from the connected Google account id
-- (Sha256(google_account_id)[..16]), the derivation every Google integration
-- shares; reconnecting the same account UPDATEs (UNIQUE(user_id,
-- provider_key)) rather than duplicating. account_email labels the settings
-- card and lets a disconnect tell which of the user's Google connections
-- share one grant (talos_oauth::google_grant).
--
-- No separate index on user_id: UNIQUE(user_id, provider_key) already serves
-- a lookup by user (a non-unique index that is a leading prefix of a sibling
-- is refused by the index-hygiene test).
--
-- No RLS policy, like google_health_integrations: every reader names the user
-- (WHERE user_id = $N) on the service pool, and no tenant-scoped connection
-- touches the table. If a tenant-scoped reader is ever added, add the policy
-- with it.

CREATE TABLE IF NOT EXISTS google_calendar_write_integrations (
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

CREATE OR REPLACE FUNCTION update_google_calendar_write_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS google_calendar_write_integrations_updated_at ON google_calendar_write_integrations;
CREATE TRIGGER google_calendar_write_integrations_updated_at
    BEFORE UPDATE ON google_calendar_write_integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_google_calendar_write_integrations_updated_at();

-- The platform-admin query tool may read this table: it holds no token, only
-- which account is connected (like google_calendar_integrations). The role
-- has no default privileges, so every new table is granted or withheld by
-- name (talos-advanced-repository/tests/admin_read_role_grants.rs).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_admin_read') THEN
        RETURN;
    END IF;
    GRANT SELECT ON public.google_calendar_write_integrations TO talos_admin_read;
END$$;
