-- Add encrypted token columns to google_calendar_integrations.
-- These mirror the pattern used by slack_integrations (bot_token_enc / access_token_enc).
-- The plaintext columns are retained for backward compatibility until a future migration
-- drops them after all rows have been back-filled with encrypted values.

ALTER TABLE google_calendar_integrations
    ADD COLUMN IF NOT EXISTS access_token_enc  BYTEA,
    ADD COLUMN IF NOT EXISTS refresh_token_enc BYTEA;
