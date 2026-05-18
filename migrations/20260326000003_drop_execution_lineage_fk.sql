-- Drop self-referential FK constraints added in 20260326000002.
-- ON DELETE SET NULL on a self-referential table installs an implicit per-row trigger that
-- serializes concurrent INSERTs touching the same table (e.g. enqueue_workflow batch loops).
-- Plain UUID columns maintain the same lineage semantics at the application layer without
-- the trigger overhead.

ALTER TABLE workflow_executions
    DROP CONSTRAINT IF EXISTS workflow_executions_parent_execution_id_fkey;

ALTER TABLE workflow_executions
    DROP CONSTRAINT IF EXISTS workflow_executions_root_execution_id_fkey;
