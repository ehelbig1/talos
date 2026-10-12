-- Jira (Atlassian) dynamic webhooks Talos has registered, and the deliveries
-- already handled.
--
-- An inbound delivery names the webhooks it matched by ATLASSIAN'S id
-- (`matchedWebhookIds`) and nothing else that says whose they are: the
-- webhook URL is one fixed address for the whole app, so it cannot carry a
-- per-user token. The receiver therefore maps a delivery to its owner by
-- webhook id, which a per-user `integration_state` lookup cannot do. Hence a
-- table of its own.
--
-- Metadata only. The OAuth tokens stay in the vault
-- (oauth/atlassian/{user_id}/{cloud_id}/access_token); `url` is this
-- deployment's own public address, not a secret.
--
-- Uniqueness and indexes:
--   * (webhook_id, cloud_id) is unique, webhook_id FIRST, so the same index
--     serves the receiver's lookup by webhook id. A separate index on
--     webhook_id would be a leading prefix of it (the index-hygiene test
--     refuses that).
--   * (user_id, cloud_id) is unique: one registration per connection, which
--     also serves every lookup by user.
--   * no index on expires_at or workflow_id: the table holds a handful of rows
--     per user, the hourly refresh reads it whole.
--
-- workflow_id is the workflow a delivery starts (set_push_channel_workflow).
-- Deleting the workflow clears the binding. The start itself re-checks
-- ownership at every delivery, so a binding is never what makes a workflow
-- startable.
--
-- refresh_failed_at / refresh_error hold the LAST failed refresh, cleared by
-- the next success, so a webhook that is about to expire because it cannot be
-- refreshed shows as such in list_push_channels.
--
-- No RLS policy, like google_health_integrations and plaid_items: the
-- receiver reads by webhook id BEFORE it knows the user (that read is what
-- finds the user), and every other reader names the user
-- (WHERE user_id = $N) on the service pool. No tenant-scoped connection
-- touches either table. If a tenant-scoped reader is ever added, add the
-- policy with it, with an arm for the receiver's lookup.

CREATE TABLE IF NOT EXISTS atlassian_webhook_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cloud_id TEXT NOT NULL,
    webhook_id BIGINT NOT NULL,
    url TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    workflow_id UUID REFERENCES workflows(id) ON DELETE SET NULL,
    last_delivery_at TIMESTAMPTZ,
    refresh_failed_at TIMESTAMPTZ,
    refresh_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (webhook_id, cloud_id),
    UNIQUE (user_id, cloud_id)
);

CREATE OR REPLACE FUNCTION update_atlassian_webhook_registrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS atlassian_webhook_registrations_updated_at ON atlassian_webhook_registrations;
CREATE TRIGGER atlassian_webhook_registrations_updated_at
    BEFORE UPDATE ON atlassian_webhook_registrations
    FOR EACH ROW
    EXECUTE FUNCTION update_atlassian_webhook_registrations_updated_at();

-- One row per (registration, X-Atlassian-Webhook-Identifier) already handled.
-- Atlassian retries a delivery up to five times with the same identifier; the
-- primary key is what makes the second one start nothing, on any replica. The
-- hourly refresh task deletes rows older than seven days, so the table is
-- bounded by a week of deliveries. Only an authenticated delivery writes here.
CREATE TABLE IF NOT EXISTS atlassian_webhook_deliveries (
    registration_id UUID NOT NULL REFERENCES atlassian_webhook_registrations(id) ON DELETE CASCADE,
    delivery_id TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (registration_id, delivery_id)
);

-- The platform-admin query tool may read both tables: neither holds a token
-- or anything a ticket says, only which webhook belongs to which connection
-- and an opaque delivery identifier. The role has no default privileges, so
-- every new table is granted or withheld by name
-- (talos-advanced-repository/tests/admin_read_role_grants.rs).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_admin_read') THEN
        RETURN;
    END IF;
    GRANT SELECT ON public.atlassian_webhook_registrations TO talos_admin_read;
    GRANT SELECT ON public.atlassian_webhook_deliveries TO talos_admin_read;
END$$;
