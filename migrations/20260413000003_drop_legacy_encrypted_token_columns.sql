-- Drop legacy encrypted token columns from Gmail and Slack integration tables.
--
-- All OAuth token storage is now handled exclusively by the unified
-- integration_credentials table via the OAuthCredentialService. The
-- encrypted columns (AES-256-GCM bytea) in the provider-specific tables
-- were the old storage path before the credential service was introduced.
--
-- Precondition verified: zero active integrations exist in Gmail or Slack
-- that have encrypted tokens without a corresponding integration_credentials
-- row. All dual-write paths have been active since the credential service
-- was wired in.
--
-- After this migration, the only token storage location is:
--   secrets table → resolved via vault://oauth/{provider}/{uid}/{key}/access_token

-- Gmail: drop encrypted token columns + the key reference
ALTER TABLE gmail_integrations
    DROP COLUMN IF EXISTS access_token_enc,
    DROP COLUMN IF EXISTS refresh_token_enc,
    DROP COLUMN IF EXISTS token_key_id;

-- Slack: drop encrypted token columns
ALTER TABLE slack_integrations
    DROP COLUMN IF EXISTS bot_token_enc,
    DROP COLUMN IF EXISTS access_token_enc;
