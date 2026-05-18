-- Store the initiating user_id with OAuth state tokens so callbacks
-- can identify the user without requiring session auth (cross-site
-- redirects from OAuth providers may not carry session cookies).
ALTER TABLE oauth_state_tokens ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id);
