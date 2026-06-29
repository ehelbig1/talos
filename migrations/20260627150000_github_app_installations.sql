-- RFC 0008 (Phase B / B2) — GitHub App installation registry.
--
-- When an operator connects a repo/org via the GitHub App install flow (B2b),
-- GitHub redirects back with an `installation_id`. We persist only METADATA
-- here — NO tokens. Installation access tokens are short-lived (1h), minted on
-- demand from the App private key (talos-github, B1) and cached by the renewal
-- arm (B3); they never live in this table.
--
-- `installation_id` is globally unique on GitHub (one row per App install), so
-- it carries a UNIQUE constraint and the connect callback upserts on it.

CREATE TABLE IF NOT EXISTS github_app_installations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The Talos user that owns this connection (the one who completed install).
    user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- GitHub's installation id (BIGINT — it exceeds i32 range).
    installation_id      BIGINT NOT NULL,
    -- The GitHub account the App is installed on (org or user login).
    account_login        TEXT NOT NULL,
    account_type         TEXT,            -- "User" | "Organization"
    -- Permissions GitHub granted the installation (echoed back; advisory).
    permissions          JSONB,
    repository_selection TEXT,            -- "all" | "selected"
    is_active            BOOLEAN NOT NULL DEFAULT true,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (installation_id)
);

-- Owner-scoped listing (list_for_user).
CREATE INDEX IF NOT EXISTS idx_github_app_installations_user_id
    ON github_app_installations (user_id);

-- B4 resolves an installation by the repo's owning account at module-dispatch
-- time; index the account lookup, scoped to live installations.
CREATE INDEX IF NOT EXISTS idx_github_app_installations_account_active
    ON github_app_installations (account_login)
    WHERE is_active;
