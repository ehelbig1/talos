-- Workflow version signing: HMAC-SHA256 signature of graph_json hash at publish time.
-- Enables tamper detection between publish and execution.

ALTER TABLE workflow_versions
    ADD COLUMN IF NOT EXISTS graph_hash TEXT,
    ADD COLUMN IF NOT EXISTS graph_signature TEXT;

COMMENT ON COLUMN workflow_versions.graph_hash IS 'SHA-256 hash of the graph_json at publish time.';
COMMENT ON COLUMN workflow_versions.graph_signature IS 'HMAC-SHA256 signature of graph_hash using TALOS_WORKFLOW_SIGNING_KEY. NULL if signing key not configured.';
