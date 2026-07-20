-- Self-monitoring bridge (execution failures → ops_alerts): durable
-- reconciler cursor + the index that makes each tick a cheap range scan.
--
-- Why a cursor-based reconciler instead of hooks at the finalizer call
-- sites: terminal `workflow_executions.status` writes happen in 8 repo
-- helpers plus ~7 inline UPDATEs (scheduler ×3, stale sweep, webhooks
-- ×3, crash recovery…), and the existing caller-side failure-notify
-- precedent already rotted by missing the scheduler arms entirely. A
-- single background tick scanning `(completed_at, id) > cursor` sees
-- every finalization by construction and can't drift as new writers
-- appear.
--
-- Cursor column choice: `completed_at` is stamped exactly once by every
-- terminal writer (audited 2026-07-20: 25/25 sites) and never bumped
-- again — unlike `updated_at`, which the BEFORE UPDATE trigger bumps on
-- pin/acknowledge of terminal rows and would re-enter processed rows
-- into the window (double occurrence-bumps).

CREATE TABLE IF NOT EXISTS ops_alerts_self_monitor_cursor (
    -- Single-row table; the CHECK pins the only legal PK value.
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    cursor_completed_at timestamptz NOT NULL,
    cursor_execution_id uuid NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000000',
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Seed at migration time so a fresh deploy alerts only on failures from
-- now on — never a backfill storm over historical rows.
INSERT INTO ops_alerts_self_monitor_cursor (singleton, cursor_completed_at)
VALUES (true, now())
ON CONFLICT (singleton) DO NOTHING;

-- Tick range scan: (completed_at, id) > (cursor_ts, cursor_id) over
-- terminal rows only. Partial → stays small and skips the hot
-- running/queued set entirely. (No CONCURRENTLY: sqlx migrations run
-- in a transaction.)
CREATE INDEX IF NOT EXISTS idx_we_self_monitor_terminal
    ON workflow_executions (completed_at, id)
    WHERE status IN ('completed', 'failed') AND completed_at IS NOT NULL;
