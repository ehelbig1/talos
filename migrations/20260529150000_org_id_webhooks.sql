-- RFC 0004 (Tenant = Organization) — M2b: org-scope the webhook domain.
--
-- `webhook_triggers` is an owned DEFINITION table (it has user_id) that
-- the M2 sweep missed — the original working set listed the long-gone
-- `webhook_listeners` name. It gets the full treatment: org_id + backfill
-- + index + the auto-stamp trigger (user-action-rate, so a per-insert
-- subquery is fine), matching actors/secrets/modules.
--
-- The two webhook LOG tables (webhook_request_log, webhook_processed_events)
-- have no user_id — they link to the trigger via trigger_id. They get
-- org_id + an index, backfilled from their parent trigger's org_id. They
-- are high-write and read app-side via the trigger join, so NEW rows are
-- left to stamp later (with RLS enablement) rather than paying a
-- per-insert subquery on a hot path; an org_id-NULL log row is harmless
-- under the current app-layer reads (RLS is not yet enabled).

-- ── webhook_triggers (definition table) ─────────────────────────────
ALTER TABLE webhook_triggers ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
UPDATE webhook_triggers x
   SET org_id = (SELECT o.id FROM organizations o WHERE o.owner_id = x.user_id AND o.is_personal)
 WHERE x.org_id IS NULL AND x.user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_triggers_org ON webhook_triggers (org_id, user_id);

DROP TRIGGER IF EXISTS trg_set_org_id ON webhook_triggers;
CREATE TRIGGER trg_set_org_id BEFORE INSERT ON webhook_triggers
    FOR EACH ROW EXECUTE FUNCTION set_org_id_from_personal_org();

-- ── webhook_request_log (child of webhook_triggers) ─────────────────
ALTER TABLE webhook_request_log ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
UPDATE webhook_request_log x
   SET org_id = (SELECT wt.org_id FROM webhook_triggers wt WHERE wt.id = x.trigger_id)
 WHERE x.org_id IS NULL AND x.trigger_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_request_log_org ON webhook_request_log (org_id);

-- ── webhook_processed_events (child of webhook_triggers) ────────────
ALTER TABLE webhook_processed_events ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
UPDATE webhook_processed_events x
   SET org_id = (SELECT wt.org_id FROM webhook_triggers wt WHERE wt.id = x.trigger_id)
 WHERE x.org_id IS NULL AND x.trigger_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_processed_events_org ON webhook_processed_events (org_id);
