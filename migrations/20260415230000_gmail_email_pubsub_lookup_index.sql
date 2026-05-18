-- Partial index on gmail_integrations.email_address to support the
-- Pub/Sub push-handler hot path:
--
--   SELECT user_id FROM gmail_integrations
--    WHERE email_address = $1 AND is_active = true LIMIT 1
--
-- Called once per incoming Pub/Sub push to resolve the mailbox
-- owner. Without this index, every push triggers a seq scan of the
-- table. The existing UNIQUE (user_id, email_address) index doesn't
-- help — its leading column is user_id, so email-only lookups can't
-- use it.
--
-- Partial filter (is_active = true) keeps the index small — most
-- rows are active, and any lookup we care about at runtime is also
-- filtered to active. Idempotent under re-apply.

CREATE INDEX IF NOT EXISTS idx_gmail_integrations_active_email
    ON gmail_integrations (email_address)
    WHERE is_active = true;
