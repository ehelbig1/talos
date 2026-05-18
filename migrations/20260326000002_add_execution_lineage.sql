-- Add parent_execution_id and root_execution_id to workflow_executions for cross-workflow
-- execution provenance. These columns let get_execution_lineage walk the full tree of
-- executions spawned by a single user action (handoffs, sub-workflows, bulk triggers).
--
-- parent_execution_id: the direct parent execution that spawned this one (NULL for top-level).
-- root_execution_id:   the originating root of the chain (NULL = this execution is the root).
--                      Stored redundantly to avoid deep CTE recursion at read time.
--
-- Design note: plain UUID (no FK constraint). FK constraints on self-referential tables with
-- ON DELETE SET NULL add implicit triggers that serialize otherwise-parallel batch inserts.
-- Referential integrity is maintained at the application layer.

ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS parent_execution_id UUID DEFAULT NULL;

ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS root_execution_id UUID DEFAULT NULL;

-- Index for fast lineage lookups (find all children of a given execution)
CREATE INDEX IF NOT EXISTS idx_workflow_executions_parent_id
    ON workflow_executions (parent_execution_id)
    WHERE parent_execution_id IS NOT NULL;

-- Index for fast root-tree scans (find all executions in a root's tree)
CREATE INDEX IF NOT EXISTS idx_workflow_executions_root_id
    ON workflow_executions (root_execution_id)
    WHERE root_execution_id IS NOT NULL;
