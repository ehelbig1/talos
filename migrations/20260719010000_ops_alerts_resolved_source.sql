-- ops_alerts.resolved_source — who/what resolved the alert.
--
-- The `__ops_alert__` envelope gains `status_event: "resolved"`
-- (auto-resolve on a source-signaled recovery, e.g. a Cloud Monitoring
-- incident closing). Operators need to distinguish "I resolved this"
-- from "the source said it recovered" when reviewing history — and a
-- signal-resolved alert that a human DISAGREES with (resolved too
-- eagerly) is future triage-training signal.
--
--   'operator' — resolved via the MCP triage surface
--   'signal'   — resolved by a status_event from the ingest pipeline
--
-- Nullable: rows resolved before this migration carry NULL (unknown).

ALTER TABLE ops_alerts
    ADD COLUMN IF NOT EXISTS resolved_source text
    CHECK (resolved_source IS NULL OR resolved_source IN ('operator', 'signal'));
