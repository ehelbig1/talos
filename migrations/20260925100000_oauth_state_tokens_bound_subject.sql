-- A flow-specific subject stored on an OAuth state row at issue time and handed
-- back by the single-use consume (`talos_oauth::ConsumedOAuthState::bound_subject`).
--
-- Why: the GitHub App connect flow no longer trusts the `installation_id` on the
-- Setup-URL redirect (GitHub documents that it can be spoofed). After the install
-- redirect it runs GitHub's user-authorization web flow and claims the
-- installation only if the authorizing GitHub user can access it
-- (`GET /user/installations`). The installation id has to cross that second
-- redirect; storing it on the state row keeps it server-side, so the second
-- callback cannot substitute a different one.
--
-- NULL for every other flow. The value is an identifier, never a credential.
-- The column is deliberately generic text (not `github_installation_id bigint`):
-- the consume is one shared implementation and should not grow a column per
-- provider.
ALTER TABLE oauth_state_tokens
    ADD COLUMN IF NOT EXISTS bound_subject TEXT;
