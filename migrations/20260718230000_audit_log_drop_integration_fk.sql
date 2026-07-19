-- Drop the integration_id FK on the shared channel-lifecycle audit log.
--
-- `google_calendar_audit_log` is (per talos-integration-helpers::audit)
-- the SHARED integration-events log for every push integration — the
-- name is inherited from the first integration. But its integration_id
-- FK still references google_calendar_integrations(id), so every row
-- whose id lives in gmail_integrations or google_cloud_integrations
-- violates the constraint. The writers are deliberately best-effort
-- (WARN + continue), which made the failure SILENT: observed live
-- 2026-07-18 as a WARN on GCP watch creation, and confirmed by the
-- table being EMPTY — gmail's channel lifecycle history has been
-- dropped this whole time too.
--
-- The FK cannot be "fixed" (one column can't reference three parent
-- tables); a per-provider audit table split would lose the shared-log
-- query surface. integration_id becomes a soft reference — fine for an
-- audit log, where rows should OUTLIVE the integration anyway (the old
-- ON DELETE CASCADE erased audit history on disconnect, which is the
-- opposite of what an audit trail is for; cf. structural-lint check 47
-- on audit tables and CASCADE).

ALTER TABLE google_calendar_audit_log
    DROP CONSTRAINT IF EXISTS google_calendar_audit_log_integration_id_fkey;

-- Soft-reference lookup support (FKs never auto-indexed in Postgres;
-- the per-integration history view filters on this).
CREATE INDEX IF NOT EXISTS idx_gcal_audit_log_integration_id
    ON google_calendar_audit_log (integration_id)
    WHERE integration_id IS NOT NULL;
