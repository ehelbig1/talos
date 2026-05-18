-- Add PKCE (RFC 7636) code_verifier storage to OAuth state tokens.
-- The verifier is generated server-side during authorization URL creation and
-- bound to the state token so it can be retrieved and included in the token
-- exchange request during the callback, preventing authorization code interception.

ALTER TABLE oauth_state_tokens
    ADD COLUMN IF NOT EXISTS pkce_verifier TEXT;
