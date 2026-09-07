-- The Gmail integration audit log has never recorded a single row.
--
-- `talos-gmail`'s `GmailIntegrationService::log_event` has always issued
-- `INSERT INTO gmail_integration_audit_log (...)`, and NO migration has ever
-- created that relation — `to_regclass('gmail_integration_audit_log')` is NULL
-- on the live database and on a freshly migrated one (measured 2026-09-07).
-- So every Gmail connect / disconnect / token-refresh event failed to insert,
-- was swallowed by `if let Err(e) = result { tracing::error!(...) }`, and left
-- a recurring ERROR line on a healthy fleet — the shape check 69 exists for.
--
-- Both sibling integrations DO have one (`slack_integration_audit_log`,
-- migration 004; `google_calendar_audit_log`), and Gmail is the only one of the
-- three with no audit trail at all. The shape below is copied clause-for-clause
-- from the Slack table so the three agree: same columns, same types, same FK
-- actions, same three indexes.
--
-- FK actions match the siblings deliberately. This table carries NO
-- `prevent_audit_modification` trigger (neither sibling does), so the
-- #264/#266 cascade-deadlock that check 47 guards cannot arise here — and
-- `gmail_integration_audit_log` is correspondingly NOT an entry in that
-- check's `AUDIT_TABLES`.

CREATE TABLE IF NOT EXISTS gmail_integration_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID REFERENCES gmail_integrations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gmail_audit_integration_id
    ON gmail_integration_audit_log(integration_id);
CREATE INDEX IF NOT EXISTS idx_gmail_audit_user_id
    ON gmail_integration_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_gmail_audit_created_at
    ON gmail_integration_audit_log(created_at DESC);

COMMENT ON TABLE gmail_integration_audit_log IS
    'Gmail OAuth/integration lifecycle events. Written by GmailIntegrationService::log_event; error_message is DLP-redacted and truncated to 1 KiB, metadata bounded to 1 MiB by redact_json_bounded.';
