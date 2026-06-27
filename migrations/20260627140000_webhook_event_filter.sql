-- RFC 0007 Phase A: optional provider-agnostic event filter on webhook triggers.
--
-- When set, the inbound handler evaluates this AFTER signature verification and
-- skips (200 OK, no workflow dispatch) deliveries that don't match — so a GitHub
-- repo webhook can fire a workflow only for, e.g., `pull_request` opened/sync,
-- without burning an execution per ignored `push`/`star`/etc. NULL = fire on
-- every verified delivery (the prior behavior — fully backward-compatible).
--
-- Shape (validated at the trigger-CRUD layer; see event_filter_matches):
--   { "header": "X-GitHub-Event",
--     "values": ["pull_request"],
--     "payload_match": { "action": ["opened","synchronize","reopened"] } }

ALTER TABLE webhook_triggers
    ADD COLUMN IF NOT EXISTS event_filter JSONB;

COMMENT ON COLUMN webhook_triggers.event_filter IS
    'RFC 0007: optional event filter evaluated AFTER signature verification. '
    'NULL = fire on every verified delivery. Shape: {header, values[], '
    'payload_match:{key:[vals]}}. Non-match → 200 OK with no dispatch.';
