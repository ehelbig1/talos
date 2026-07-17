-- Ops-alerts domain: the durable store behind the alert-triage pipeline.
--
-- Normalized operational alerts ingested from ANY source (email-derived
-- Snyk/AWS-Health/ServiceNow notifications, GCP Monitoring via Pub/Sub
-- push, generic webhooks). Parser catalog modules emit normalized
-- alerts via the opt-in `__ops_alert__` node-output hook (sibling of
-- `__memory_write__`); the engine's ControllerNodeHook persists them
-- here with tenancy derived from the execution's bound actor.
--
-- Dedup: UNIQUE(user_id, dedup_key). Re-ingesting the same fingerprint
-- bumps occurrence_count/last_seen instead of duplicating; a re-fired
-- alert that was already `resolved` REOPENS to `new` (regression
-- signal), but a bump NEVER clobbers `severity` — triage labels and
-- especially human corrections (the distillation gold set) survive
-- re-ingestion.
--
-- Tenancy posture: NO RLS, service-layer `WHERE user_id = $N` —
-- deliberately mirrors actor_memory (the `__memory_write__` sibling
-- store) and the gmail/gcal/gcloud integration tables, because the
-- engine-hook write path runs on the bare pool from a spawned task,
-- not a tenant-scoped transaction. `org_id` is stamped for future
-- org-shared triage views.
--
-- `raw` holds the DLP-REDACTED source payload (redacted BEFORE
-- persistence — alert bodies routinely embed tokens/URLs), bounded by
-- the ingest path; NULL when the payload was oversized or absent.

CREATE TABLE IF NOT EXISTS ops_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    external_id TEXT,
    dedup_key TEXT NOT NULL,
    title TEXT NOT NULL,
    resource TEXT,
    severity_raw TEXT,
    severity TEXT NOT NULL DEFAULT 'unclassified'
        CHECK (severity IN ('critical','high','medium','low','info','noise','unclassified')),
    triage_source TEXT,
    triage_confidence REAL,
    corrected_severity TEXT
        CHECK (corrected_severity IS NULL
               OR corrected_severity IN ('critical','high','medium','low','info','noise')),
    corrected_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new','acked','resolved')),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    raw JSONB,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acked_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    UNIQUE (user_id, dedup_key)
);

-- Primary listing path: "my active alerts, most recent first". id DESC
-- tiebreaker keeps OFFSET/keyset pagination stable (lint 28 class).
CREATE INDEX IF NOT EXISTS idx_ops_alerts_user_status_last_seen
    ON ops_alerts (user_id, status, last_seen DESC, id DESC);

-- Severity rollups over the active set (digest counts).
CREATE INDEX IF NOT EXISTS idx_ops_alerts_user_severity_active
    ON ops_alerts (user_id, severity)
    WHERE status <> 'resolved';

-- Correction-mining path for the future classifier distillation loop.
CREATE INDEX IF NOT EXISTS idx_ops_alerts_user_corrected
    ON ops_alerts (user_id, corrected_at DESC)
    WHERE corrected_severity IS NOT NULL;
