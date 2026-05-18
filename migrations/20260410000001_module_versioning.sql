-- Module semantic versioning support.
-- Enables version pinning in workflows and version-aware cache keys.

ALTER TABLE wasm_modules
    ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT '1.0.0',
    ADD COLUMN IF NOT EXISTS version_tag TEXT;

-- Unique constraint: same module name+version per user cannot coexist.
-- Uses a partial index to avoid issues with NULL user_id (system modules).
CREATE UNIQUE INDEX IF NOT EXISTS idx_wasm_modules_name_version_user
    ON wasm_modules (name, version, user_id)
    WHERE user_id IS NOT NULL;

COMMENT ON COLUMN wasm_modules.version IS 'Semantic version (e.g., 1.2.0). Auto-incremented on recompile of same-named module.';
COMMENT ON COLUMN wasm_modules.version_tag IS 'Optional human-readable tag (e.g., stable, beta, canary).';
