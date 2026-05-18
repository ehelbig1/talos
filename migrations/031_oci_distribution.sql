-- Migration 031: Add OCI Registry Support for WASM Distribution

ALTER TABLE node_templates 
ADD COLUMN IF NOT EXISTS oci_url TEXT;

ALTER TABLE wasm_modules 
ADD COLUMN IF NOT EXISTS oci_url TEXT;

COMMENT ON COLUMN node_templates.oci_url IS 'Optional OCI Artifact registry URL (e.g., oci://ghcr.io/org/talos-tools/my-module:v1.0.0)';
COMMENT ON COLUMN wasm_modules.oci_url IS 'Optional OCI Artifact registry URL for the compiled Wasm binary';
