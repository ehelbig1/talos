-- Per-workflow-execution log capture.
--
-- Today's `module_execution_logs.execution_id` has a hard FK to
-- `module_executions(id)` (migration 012, renamed in 015). When workers
-- publish to `wasm.log.{execution_id}` for a workflow execution, the
-- subscriber's INSERT silently no-ops because the FK lookup fails — the
-- execution_id is a workflow_executions.id, not a module_executions.id.
-- Result: workflow-execution logs are dropped on the floor and there's
-- no operator surface for `tail_worker_logs`.
--
-- This migration adds a parallel `workflow_execution_logs` table scoped
-- by workflow_execution_id, with the same per-execution rate limit (5000
-- entries; higher than module_execution_logs' 1000 because workflows
-- have many nodes). The wasm-log subscriber then picks the right table
-- based on which execution kind the ID belongs to.

CREATE TABLE IF NOT EXISTS workflow_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES workflow_executions(id) ON DELETE CASCADE,
    -- Optional node id when the log is associated with a specific workflow
    -- node. Lets `tail_worker_logs(node_id: ...)` filter logs to one node.
    node_id UUID,
    level TEXT NOT NULL CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR')),
    message TEXT NOT NULL,
    -- Structured metadata; bounded to ~16 KiB at insert time by the
    -- controller-side validator (matches module_execution_logs).
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot-path indexes (mirror module_execution_logs):
--   - by execution_id (full tail)
--   - by (execution_id, created_at) for tail-with-since
--   - by (execution_id, level) for tail-by-level
--   - partial by node_id for per-node filtering
CREATE INDEX IF NOT EXISTS idx_workflow_execution_logs_exec
    ON workflow_execution_logs(execution_id);
CREATE INDEX IF NOT EXISTS idx_workflow_execution_logs_exec_created
    ON workflow_execution_logs(execution_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_workflow_execution_logs_exec_level
    ON workflow_execution_logs(execution_id, level);
CREATE INDEX IF NOT EXISTS idx_workflow_execution_logs_node
    ON workflow_execution_logs(execution_id, node_id)
    WHERE node_id IS NOT NULL;

-- Per-execution rate cap: refuse INSERTs once 5000 entries exist for a
-- given execution_id. Mirrors module_execution_logs's trigger semantics
-- (which uses an O(1) counter column on module_executions). Workflow
-- executions don't carry a log_count column today, so this trigger is
-- O(N) for N existing rows — acceptable since (a) workflow executions
-- are short-lived (minutes) and (b) the index on execution_id makes
-- the COUNT a fast index-only scan. If we ever see hot workflows with
-- 4900+ logs the cheap fix is to add a `log_count` BIGINT column to
-- workflow_executions and a counter trigger.
CREATE OR REPLACE FUNCTION enforce_workflow_log_limit()
RETURNS TRIGGER AS $$
DECLARE
    n BIGINT;
BEGIN
    SELECT COUNT(*) INTO n
    FROM workflow_execution_logs
    WHERE execution_id = NEW.execution_id;
    IF n >= 5000 THEN
        RAISE EXCEPTION 'workflow_execution_logs limit reached for execution % (5000 entries)', NEW.execution_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS workflow_log_count_enforce_limit ON workflow_execution_logs;
CREATE TRIGGER workflow_log_count_enforce_limit
    BEFORE INSERT ON workflow_execution_logs
    FOR EACH ROW
    EXECUTE FUNCTION enforce_workflow_log_limit();

COMMENT ON TABLE workflow_execution_logs IS
    'Per-workflow-execution log capture from worker WASM modules. Parallel to module_execution_logs (which is for standalone module/node executions). The wasm-log subscriber routes to whichever table matches the execution_id.';
COMMENT ON COLUMN workflow_execution_logs.node_id IS
    'Optional graph node UUID this log line came from. NULL for execution-level logs.';
