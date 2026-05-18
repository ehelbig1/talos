-- Add security improvements to Google Calendar watch channels
-- Ensure the pgcrypto extension is available for gen_random_bytes.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- 1. Verification token for webhook authentication
-- 2. Message number tracking for deduplication

ALTER TABLE google_calendar_watch_channels
ADD COLUMN IF NOT EXISTS verification_token TEXT,
ADD COLUMN IF NOT EXISTS last_message_number BIGINT DEFAULT 0;

-- Create index for fast token lookup during webhook verification
CREATE INDEX IF NOT EXISTS idx_watch_channels_channel_id_active
ON google_calendar_watch_channels(channel_id, is_active)
WHERE is_active = true;

-- Backfill verification tokens for existing channels
-- Use a random 64-character hex string (32 bytes)
UPDATE google_calendar_watch_channels
SET verification_token = encode(gen_random_bytes(32), 'hex')
WHERE verification_token IS NULL;

-- Make verification_token NOT NULL after backfill
ALTER TABLE google_calendar_watch_channels
ALTER COLUMN verification_token SET NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN google_calendar_watch_channels.verification_token IS
'Random secret token sent with watch channel creation. Used to verify webhook notifications are from Google.';

COMMENT ON COLUMN google_calendar_watch_channels.last_message_number IS
'Last processed message number from X-Goog-Message-Number header. Used for deduplication.';
