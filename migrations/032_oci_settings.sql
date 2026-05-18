-- Migration 031: Workspace OCI Settings and Module OCI Support

CREATE TABLE workspace_oci_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    registry_url TEXT NOT NULL,
    username TEXT,
    password_encrypted BYTEA,
    password_nonce BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_workspace_oci_settings_updated_at
    BEFORE UPDATE ON workspace_oci_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

ALTER TABLE node_templates 
ADD COLUMN IF NOT EXISTS oci_url TEXT;

ALTER TABLE wasm_modules 
ADD COLUMN IF NOT EXISTS oci_url TEXT;

COMMENT ON COLUMN node_templates.oci_url IS 'Optional OCI Artifact registry URL (e.g., oci://ghcr.io/org/talos-tools/my-module:v1.0.0)';
COMMENT ON COLUMN wasm_modules.oci_url IS 'Optional OCI Artifact registry URL for the compiled Wasm binary';
