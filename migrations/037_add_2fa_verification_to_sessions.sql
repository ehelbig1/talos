-- Migration: Add is_2fa_verified to user_sessions
-- This allows tracking if a session has been 2FA verified, ensuring that
-- refreshed access tokens maintain their 2FA verification status.

ALTER TABLE user_sessions ADD COLUMN is_2fa_verified BOOLEAN NOT NULL DEFAULT false;

-- Audit block
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'user_sessions'
        AND column_name = 'is_2fa_verified'
    ) THEN
        RAISE EXCEPTION 'Migration failed: is_2fa_verified column not added to user_sessions';
    END IF;
END $$;
