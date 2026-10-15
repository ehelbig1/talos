-- Row security on `oauth_state_tokens` (security review 2026-10-14, C-9).
--
-- The table holds the pending consents of every user (a connect flow's row
-- names its user; a login flow's row has none) and had no policy: any session
-- scoped to one user could read every user's pending state, PKCE verifier and
-- binding hash. Same shape as the other tenant tables: a session scoped to a
-- user (`app.current_user_id` set) sees only that user's rows; an unscoped
-- session — every statement the OAuth flows run today, on the bare pool —
-- is unchanged. A login row (no user) is visible to unscoped sessions only.
--
-- The platform-admin read role already cannot read it (`BLOCKED_TABLES_LIST`,
-- MCP-1002).

ALTER TABLE oauth_state_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_state_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_state_tokens_user_isolation ON oauth_state_tokens;
CREATE POLICY oauth_state_tokens_user_isolation ON oauth_state_tokens
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

CREATE INDEX IF NOT EXISTS idx_oauth_state_tokens_user_id
    ON oauth_state_tokens (user_id) WHERE user_id IS NOT NULL;
