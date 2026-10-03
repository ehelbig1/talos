-- Bank connections made through Plaid Link (one row per Plaid Item: one bank
-- login, which may cover several accounts).
--
-- Metadata only. The Item's access token lives in the vault at
-- plaid/access_token/{item_id} (talos_plaid::link::access_token_path), owned
-- by the user, where a reader module reaches it through a vault:// reference
-- under its `plaid/*` grant.
--
-- item_id is Plaid's own identifier; reconnecting the same Item UPDATEs
-- (UNIQUE(user_id, item_id)). institution_name is a display label.
--
-- No separate index on user_id: the UNIQUE index's leading column serves a
-- lookup by user. No RLS policy, like google_health_integrations: every
-- reader names the user (WHERE user_id = $N) on the service pool.

CREATE TABLE IF NOT EXISTS plaid_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL,
    institution_id TEXT,
    institution_name TEXT,
    environment TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, item_id)
);

CREATE OR REPLACE FUNCTION update_plaid_items_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS plaid_items_updated_at ON plaid_items;
CREATE TRIGGER plaid_items_updated_at
    BEFORE UPDATE ON plaid_items
    FOR EACH ROW
    EXECUTE FUNCTION update_plaid_items_updated_at();
