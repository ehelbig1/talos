-- Extend the workflow_versions sync trigger to also fire on INSERT.
--
-- The original trigger (20260413000001) only fired on UPDATE OF graph_json.
-- A brand-new workflow created with graph_json already populated would not
-- sync to workflow_versions on INSERT. Adding OR INSERT covers this case.
-- The function already handles both: it compares OLD vs NEW for UPDATEs
-- and always syncs for INSERTs (where OLD is NULL → IS DISTINCT FROM is true).

-- Recreate the function to handle INSERT (OLD is NULL for inserts).
CREATE OR REPLACE FUNCTION sync_active_version_graph()
RETURNS TRIGGER AS $$
BEGIN
    -- For INSERT: always sync if graph_json is non-null.
    -- For UPDATE: only sync when graph_json actually changed.
    IF TG_OP = 'INSERT' OR (OLD.graph_json IS DISTINCT FROM NEW.graph_json) THEN
        UPDATE workflow_versions
           SET graph_json = NEW.graph_json::jsonb,
               updated_at = NOW()
         WHERE workflow_id = NEW.id
           AND is_active = true;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sync_workflow_version_graph ON workflows;

CREATE TRIGGER trg_sync_workflow_version_graph
    AFTER INSERT OR UPDATE OF graph_json ON workflows
    FOR EACH ROW
    EXECUTE FUNCTION sync_active_version_graph();
