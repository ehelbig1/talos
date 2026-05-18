-- Fix sync_active_version_graph trigger: the function references
-- workflow_versions.updated_at which does not exist on the table.
-- Add the column and recreate the function.

ALTER TABLE workflow_versions
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Recreate the trigger function (unchanged logic, just ensuring it
-- matches the now-existing column).
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
