-- Add notification_webhook to workflow_approval_gates.
-- When set, the platform fires an HTTP POST to this URL immediately after
-- gate creation so human reviewers are notified out-of-band without polling.
-- Storing the URL on the row lets test_approval_webhook retrieve it later
-- for connectivity verification.

ALTER TABLE workflow_approval_gates
    ADD COLUMN IF NOT EXISTS notification_webhook TEXT;
