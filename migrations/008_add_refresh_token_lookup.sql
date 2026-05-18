-- Migration 008: Add refresh_token_lookup_hash column
-- This column is used for efficient token lookups without exposing the full hash

ALTER TABLE user_sessions
    ADD COLUMN IF NOT EXISTS refresh_token_lookup_hash TEXT;

-- Index for fast lookups
CREATE INDEX IF NOT EXISTS idx_user_sessions_lookup_hash
    ON user_sessions(refresh_token_lookup_hash)
    WHERE refresh_token_lookup_hash IS NOT NULL;
