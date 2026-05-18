-- Add integration_name to module tables so the engine can propagate it
-- to the worker as part of JobRequest. Modules that persist integration
-- state use this to scope their writes; nullable because most modules
-- are NOT integrations and shouldn't touch integration_state at all.
--
-- Stored on BOTH node_templates and wasm_modules because:
--   - node_templates is the source-of-truth when an inline sandbox is
--     compiled (no wasm_modules row until first dispatch).
--   - wasm_modules is what the engine reads at dispatch time; carrying
--     the field here avoids a secondary lookup hot-path.
-- The compile_custom_sandbox + add_node_to_workflow upsert paths set
-- both in one atomic block.
--
-- Every ADD runs only if not already present: the column ADDs use
-- `IF NOT EXISTS`, and the CHECK constraints are wrapped in DO blocks
-- that probe pg_constraint first. Idempotency matters because the
-- constraints may have been applied out-of-band (e.g. manual
-- `docker exec psql` during development) BEFORE sqlx tracked the
-- migration — re-running a plain `ADD CONSTRAINT` would fail on
-- "constraint already exists" and block every subsequent deploy.

ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS integration_name TEXT;

ALTER TABLE wasm_modules
    ADD COLUMN IF NOT EXISTS integration_name TEXT;

-- Match the integration_state CHECK so modules cannot declare an
-- integration_name that would be rejected at the RPC layer. Enforcing
-- here catches bad declarations at compile time instead of at first
-- RPC call with a cryptic Unauthorized.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'node_templates_integration_name_chk'
    ) THEN
        ALTER TABLE node_templates
            ADD CONSTRAINT node_templates_integration_name_chk
            CHECK (integration_name IS NULL OR
                   (length(integration_name) > 0 AND length(integration_name) <= 64
                    AND integration_name ~ '^[a-z0-9_-]+$'));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'wasm_modules_integration_name_chk'
    ) THEN
        ALTER TABLE wasm_modules
            ADD CONSTRAINT wasm_modules_integration_name_chk
            CHECK (integration_name IS NULL OR
                   (length(integration_name) > 0 AND length(integration_name) <= 64
                    AND integration_name ~ '^[a-z0-9_-]+$'));
    END IF;
END $$;
