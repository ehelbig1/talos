-- Optimise the sibling-cancel trigger and add a composite index for the
-- cancellation UPDATE query pattern.
--
-- 1. Composite index on (workflow_execution_id, status)
--    The cancellation UPDATE fires the pattern:
--      UPDATE module_executions
--        SET status = 'cancelled', ...
--       WHERE workflow_execution_id = $1 AND status = 'running'
--    The existing partial index (workflow_execution_id WHERE NOT NULL) lets
--    Postgres narrow to the right execution, but it still re-checks status
--    for every row in that set.  A composite index allows a single index range
--    scan with no extra heap filter for the common case.
--
-- 2. Restrict trigger to UPDATE OF status
--    The previous trigger fired on every UPDATE to workflow_executions —
--    checkpoint flushes, output writes, pin toggles, etc. — even though the
--    function body immediately exits unless NEW.status = 'failed'.  Adding
--    OF status means the trigger fires only when the status column is included
--    in the SET clause, eliminating unnecessary invocations.

CREATE INDEX IF NOT EXISTS idx_module_executions_wf_exec_status
    ON module_executions (workflow_execution_id, status)
    WHERE workflow_execution_id IS NOT NULL;

-- Re-create the trigger with the column-level filter.
-- cancel_siblings_on_workflow_fail() was created by migration
-- 20260327000001; we only change when the trigger fires, not the function.
DROP TRIGGER IF EXISTS trg_cancel_siblings_on_workflow_fail ON workflow_executions;

CREATE TRIGGER trg_cancel_siblings_on_workflow_fail
    AFTER UPDATE OF status ON workflow_executions
    FOR EACH ROW
    EXECUTE FUNCTION cancel_siblings_on_workflow_fail();
