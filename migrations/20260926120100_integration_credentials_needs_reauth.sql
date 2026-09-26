-- Record that a credential's grant was REVOKED at the provider.
--
-- The proactive refresh task retried a revoked refresh token (HTTP 400
-- `invalid_grant`) every five minutes forever, logging an ERROR each time.
-- `needs_reauth_at` is stamped when the token endpoint answers
-- `invalid_grant`; refresh is then skipped until the user re-links (the
-- credential upsert clears it). NULL = healthy / never refused.
ALTER TABLE integration_credentials
    ADD COLUMN IF NOT EXISTS needs_reauth_at TIMESTAMPTZ;
