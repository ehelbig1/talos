-- Optimistic concurrency for `workflows.graph_json`.
--
-- Every graph mutation tool (update_node_config, add_node_to_workflow,
-- add_edge, add_skip_condition, the add_*_node family, set_workflow_priority,
-- analyze_execution_failure's auto-fix, …) is a READ-MODIFY-WRITE of the whole
-- graph: read `graph_json`, change one node in Rust, write the whole document
-- back. The write was an unconditional `UPDATE … SET graph_json = $1`, so two
-- overlapping calls — MCP clients issue tool calls in parallel, and the web
-- editor holds a graph open for minutes — each wrote their own copy and the
-- second silently discarded the first one's change. No error, no log line:
-- the losing call still answered "node added".
--
-- `graph_version` is a per-row counter the writers compare against the value
-- they read (`… AND graph_version = $n RETURNING graph_version`). Zero rows
-- matched on a row that exists is a CONFLICT, surfaced to the caller instead
-- of an overwrite.
--
-- The column is OWNED BY THE TRIGGER below, not by the writers: it advances
-- exactly when `graph_json` changes, on EVERY writer — including the ones
-- that are deliberately unconditional (rollback to a published version, the
-- GraphQL update without an expected version, imports). So a read-modify-write
-- that races any of them still sees the conflict. A writer cannot set the
-- column itself: an explicit value is overwritten with the trigger's answer,
-- so a buggy `SET graph_version = 0` cannot re-open a window.
--
-- The trigger is named `trg_…` so it sorts BEFORE `update_workflows_updated_at`
-- (BEFORE-row triggers fire in name order): the updated_at trigger compares
-- NEW against OLD column by column, and it should see the corrected
-- `graph_version`, never a writer-supplied one.
--
-- DEFAULT 1 on a NOT NULL column is a catalog-only change on PG ≥ 11 (a
-- non-volatile default is not written into existing tuples), so this does not
-- rewrite the table.
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS graph_version BIGINT NOT NULL DEFAULT 1;

CREATE OR REPLACE FUNCTION talos_bump_workflow_graph_version()
    RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.graph_json IS DISTINCT FROM OLD.graph_json THEN
        NEW.graph_version := OLD.graph_version + 1;
    ELSE
        NEW.graph_version := OLD.graph_version;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_workflows_graph_version
    BEFORE UPDATE ON workflows
    FOR EACH ROW
    EXECUTE FUNCTION talos_bump_workflow_graph_version();

COMMENT ON COLUMN workflows.graph_version IS
    'Advances by one whenever graph_json changes (trigger-owned; writers cannot '
    'set it). Read-modify-write callers pass the value they read and write only '
    'if it is unchanged — see talos_workflow_repository::graph_version.';
