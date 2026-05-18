-- Add 'cancelled' to the module_executions status check constraint.
--
-- The sibling-cancellation fix (20260327000001) sets module_executions.status
-- to 'cancelled' for parallel nodes that were still running when a sibling
-- failed.  Without this migration the UPDATE violates the existing check
-- constraint (which only allows pending/running/completed/failed/timeout),
-- causing the DB trigger — and the application-level cancellation UPDATEs —
-- to fail silently or roll back the parent transaction.
--
-- workflow_executions already allows 'cancelled'; this brings module_executions
-- into parity.

-- Drop the existing constraint and re-create with the expanded set.
ALTER TABLE module_executions
    DROP CONSTRAINT IF EXISTS node_executions_status_check;

ALTER TABLE module_executions
    ADD CONSTRAINT node_executions_status_check
    CHECK (status = ANY (ARRAY[
        'pending'::text,
        'running'::text,
        'completed'::text,
        'failed'::text,
        'timeout'::text,
        'cancelled'::text
    ]));
