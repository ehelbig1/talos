-- Atlassian (Jira) OAuth integrations.
-- Stores cloud instance metadata; tokens live in integration_credentials + secrets (unified path).
CREATE TABLE IF NOT EXISTS atlassian_integrations (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cloud_id        VARCHAR(255) NOT NULL,
    site_url        TEXT        NOT NULL,
    display_name    TEXT,
    scope           TEXT,
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, cloud_id)
);

CREATE INDEX IF NOT EXISTS idx_atlassian_integrations_user ON atlassian_integrations(user_id);
