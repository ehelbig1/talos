-- Crash recovery (RFC 0003 durable execution): add the `resuming` status to
-- the workflow_executions CHECK constraint.
--
-- `resuming` is a short-lived CLAIM/lease state used by the controller-startup
-- crash-recovery sweep: an orphaned `running` execution (its controller crashed
-- mid-run) is atomically flipped `running` → `resuming` by exactly one replica
-- (status-guarded UPDATE + FOR UPDATE SKIP LOCKED), which both (a) guarantees
-- only one replica resumes it and (b) removes it from every `WHERE status =
-- 'running'` cleanup predicate so it can't be failed out from under recovery.
-- The checkpoint loader reads `resuming` (alongside `waiting`); the engine's
-- terminal write moves it back to running/completed/failed/waiting.
--
-- Mirrors 20260319000000_add_waiting_execution_status.sql exactly — a missing
-- value here would make the claim UPDATE silently affect 0 rows (the CHECK
-- rejects it), the same class of bug that migration was created to fix.
ALTER TABLE workflow_executions DROP CONSTRAINT IF EXISTS workflow_executions_status_check;
ALTER TABLE workflow_executions ADD CONSTRAINT workflow_executions_status_check
    CHECK (status IN ('running', 'completed', 'failed', 'cancelled', 'queued', 'waiting', 'resuming'));
