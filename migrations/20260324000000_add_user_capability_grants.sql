-- Migration: Add user capability grants table for Human RBAC
-- Tracks per-user capability ceiling grants. Without a grant, the default ceiling
-- is 'http-node' (conservative). Admins can elevate users up to their own ceiling.

CREATE TABLE IF NOT EXISTS user_capability_grants (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    max_capability_world TEXT        NOT NULL DEFAULT 'http-node',
    granted_by           UUID        REFERENCES users(id),
    granted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes                TEXT,
    CONSTRAINT ucg_world_check CHECK (max_capability_world IN (
        'minimal-node','http-node','standard-node','network-node',
        'secrets-node','governance-node','messaging-node','filesystem-node',
        'cache-node','database-node','automation-node','full-node'
    )),
    UNIQUE (user_id)
);

CREATE INDEX IF NOT EXISTS idx_ucg_user ON user_capability_grants(user_id);
