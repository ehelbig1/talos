-- Drop legacy encrypted token columns from google_calendar_integrations.
--
-- Tokens are now stored exclusively in the unified `integration_credentials`
-- table via the `OAuthCredentialService` (vault path:
-- oauth/google_calendar/{user_id}/{account_id}/access_token). The
-- `access_token_enc` and `refresh_token_enc` bytea columns were from
-- an earlier migration that predated the credential service; their
-- presence invited code that bypassed the unified refresh path.
--
-- The create_or_update_integration function (google_calendar/mod.rs)
-- was updated in commit ee34535 to stop writing to these columns.
-- The custom refresh_token_if_needed function that read from them was
-- removed in the consolidation commit. No code path reads or writes
-- these columns anymore.

ALTER TABLE google_calendar_integrations
    DROP COLUMN IF EXISTS access_token_enc,
    DROP COLUMN IF EXISTS refresh_token_enc;
