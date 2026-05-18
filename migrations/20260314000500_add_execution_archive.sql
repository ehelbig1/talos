-- Execution archival table: stores old completed/failed/cancelled executions
-- moved from workflow_executions by the background archival task.
CREATE TABLE IF NOT EXISTS workflow_executions_archive (
    LIKE workflow_executions INCLUDING ALL
);

CREATE INDEX IF NOT EXISTS idx_archive_user_started
    ON workflow_executions_archive(user_id, started_at DESC);
