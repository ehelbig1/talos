-- Junction table: tracks which module UUIDs appear in each workflow's graph_json.
-- Replaces the full-table LIKE '%uuid%' scan in workflow_chains.rs with an indexed
-- equi-join, eliminating sequential scans on large workflow tables.
CREATE TABLE workflow_module_refs (
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    module_id   UUID NOT NULL,
    PRIMARY KEY (workflow_id, module_id)
);

CREATE INDEX idx_wmr_module_id ON workflow_module_refs(module_id);

-- Supports the DISTINCT ON polling query in latest_workflow_executions.
CREATE INDEX IF NOT EXISTS idx_we_workflow_started
    ON workflow_executions(workflow_id, started_at DESC);

-- Backfill existing rows from graph_json nodes.
INSERT INTO workflow_module_refs (workflow_id, module_id)
SELECT
    w.id                                           AS workflow_id,
    (node->>'moduleId')::uuid                      AS module_id
FROM
    workflows w,
    jsonb_array_elements(w.graph_json::jsonb->'nodes') AS node
WHERE
    node->>'moduleId' IS NOT NULL
    AND node->>'moduleId' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
ON CONFLICT DO NOTHING;
