-- Prevent workflow_versions from diverging when workflows.graph_json is
-- updated directly (e.g. via SQL or a handler that modifies graph_json
-- without calling publish_version). The trigger fires AFTER UPDATE on
-- the workflows table and propagates the new graph_json to the active
-- version row in workflow_versions.
--
-- This closes a class of bugs where:
--   - An operator updates a node config via direct SQL
--   - The workflows.graph_json is modified correctly
--   - But trigger_workflow reads from workflow_versions (the published
--     version), which still has the stale graph
--   - The workflow executes with the old config
--
-- The trigger only fires when graph_json actually changes (OLD.graph_json
-- IS DISTINCT FROM NEW.graph_json) to avoid unnecessary writes on
-- unrelated column updates. It targets only the active version
-- (is_active = true) — inactive/historical versions are preserved.

CREATE OR REPLACE FUNCTION sync_active_version_graph()
RETURNS TRIGGER AS $$
BEGIN
    -- Only sync when graph_json actually changed
    IF OLD.graph_json IS DISTINCT FROM NEW.graph_json THEN
        UPDATE workflow_versions
           SET graph_json = NEW.graph_json::jsonb,
               updated_at = NOW()
         WHERE workflow_id = NEW.id
           AND is_active = true;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop if exists to make the migration idempotent
DROP TRIGGER IF EXISTS trg_sync_workflow_version_graph ON workflows;

CREATE TRIGGER trg_sync_workflow_version_graph
    AFTER UPDATE OF graph_json ON workflows
    FOR EACH ROW
    EXECUTE FUNCTION sync_active_version_graph();
