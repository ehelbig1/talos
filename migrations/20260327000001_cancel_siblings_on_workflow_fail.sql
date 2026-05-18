-- Auto-cancel running module_executions when a workflow transitions to 'failed'.
--
-- Motivation: parallel siblings that were dispatched when another node failed are
-- left stuck at status='running' indefinitely unless explicitly transitioned.  The
-- previous application-level UPDATE (in workflow_chains.rs) only covers one of many
-- failure paths.  A DB trigger fires for ALL failure paths regardless of where in the
-- codebase the workflow_executions.status update originates:
--   • workflow_chains.rs  (trigger-based workflow runs)
--   • api/schema/mutations.rs  (GraphQL trigger_workflow)
--   • scheduler.rs  (scheduled runs)
--   • webhooks/mod.rs  (webhook-triggered runs)
--   • mcp/advanced.rs  (MCP-triggered runs)
--
-- Safety:
--   • AFTER UPDATE, FOR EACH ROW — fires once per updated row, never for inserts.
--   • OLD.status guard prevents re-entrancy if status is already 'failed'.
--   • The trigger runs in the same transaction as the workflow_executions UPDATE,
--     so the cancellation is atomic (both succeed or both roll back).
--   • complete_execution_from_worker / fail_execution_from_worker both use
--     WHERE status IN ('pending', 'running'), so a worker response arriving after
--     cancellation is a safe no-op.

CREATE OR REPLACE FUNCTION cancel_siblings_on_workflow_fail()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'failed'
       AND (OLD.status IS NULL OR OLD.status <> 'failed')
    THEN
        UPDATE module_executions
        SET status        = 'cancelled',
            completed_at  = NOW(),
            error_message = 'Workflow failed — parallel sibling cancelled'
        WHERE workflow_execution_id = NEW.id
          AND status = 'running';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_cancel_siblings_on_workflow_fail
    AFTER UPDATE ON workflow_executions
    FOR EACH ROW
    EXECUTE FUNCTION cancel_siblings_on_workflow_fail();
