-- General-purpose append-only admin event log.
-- Records lifecycle events for privileged resources that are not modelled as
-- actor_action_log entries (e.g. MCP agent registration/revocation).
-- Append-only design: no UPDATE or DELETE permissions are granted in application
-- code; revocations are recorded as new 'revoked' events, not deletions.

CREATE TABLE IF NOT EXISTS admin_event_log (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        REFERENCES users(id) ON DELETE SET NULL,
    event_type   TEXT        NOT NULL,
    resource_type TEXT       NOT NULL,  -- 'mcp_agent', 'actor', etc.
    resource_id  UUID,
    summary      TEXT        NOT NULL,
    details      JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_event_log_user_id
    ON admin_event_log(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_event_log_resource
    ON admin_event_log(resource_type, resource_id);

CREATE INDEX IF NOT EXISTS idx_admin_event_log_created_at
    ON admin_event_log(created_at DESC);
