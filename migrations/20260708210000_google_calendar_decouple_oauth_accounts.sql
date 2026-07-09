-- Decouple google_calendar_integrations from the SSO-login `oauth_accounts` table.
--
-- The Calendar "Connect" flow historically piggybacked on the Google SSO login
-- callback (/auth/oauth/google/callback), which refuses to auto-link a Google
-- identity onto an existing password account (anti-hijack guard) and 500s. The
-- new dedicated Calendar OAuth flow (talos-google-calendar `OAuthIntegration`)
-- mirrors Gmail/Slack: it derives a STABLE `oauth_account_id` from the Google
-- account id and stores tokens at
--   oauth/google_calendar/{user_id}/{oauth_account_id}/{access,refresh}_token
-- via OAuthCredentialService. It does NOT create an `oauth_accounts`
-- (login-identity) row, so the foreign key must be dropped. The legacy
-- SSO-piggyback path still passes a real `oauth_accounts.id`, which remains a
-- perfectly valid UUID for the (now unconstrained) column — both paths coexist.
ALTER TABLE google_calendar_integrations
    DROP CONSTRAINT IF EXISTS google_calendar_integrations_oauth_account_id_fkey;

-- Human-readable connected-account label for the settings UI, set by the
-- dedicated connect flow. Legacy rows leave it NULL; the list handler falls
-- back to the `oauth_accounts` email for those (they still have a real
-- oauth_account_id that references a login identity).
ALTER TABLE google_calendar_integrations
    ADD COLUMN IF NOT EXISTS account_email TEXT;
