-- ops_alerts.reopened_at — precise reopen tracking (canary refinement,
-- 2026-07-17).
--
-- The ingest upsert flips a re-fired `resolved` alert back to `new` and
-- CLEARS resolved_at, which makes a true reopen indistinguishable
-- post-hoc from a plain bump. The digest's `reopened_active` count
-- therefore approximated with `occurrence_count > 1 AND ...` — which
-- counts bumped-while-new rows too (observed live: 4 "reopened" that
-- were really just dedup bumps of never-resolved alerts).
--
-- `reopened_at` is stamped by the ingest upsert at the moment a
-- resolved row reopens, and only then — a bump of a new/acked row
-- leaves it untouched. NULL = never reopened.

ALTER TABLE ops_alerts ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ;

-- Digest path: "active alerts that regressed after being resolved".
CREATE INDEX IF NOT EXISTS idx_ops_alerts_user_reopened_active
    ON ops_alerts (user_id)
    WHERE reopened_at IS NOT NULL AND status <> 'resolved';
