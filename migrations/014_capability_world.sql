-- Migration 014: Capability metadata for WASM modules
--
-- Stores the WIT capability world and imported interfaces detected by binary
-- inspection after compilation.  This lets us query AI tool schemas without
-- re-scanning WASM bytes on every request.

ALTER TABLE wasm_modules
    ADD COLUMN IF NOT EXISTS capability_world TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS imported_interfaces TEXT[] NOT NULL DEFAULT '{}';

-- Constrain to known capability world values
ALTER TABLE wasm_modules
    DROP CONSTRAINT IF EXISTS wasm_modules_capability_world_check;
ALTER TABLE wasm_modules
    ADD CONSTRAINT wasm_modules_capability_world_check
    CHECK (capability_world IN ('minimal', 'network', 'trusted', 'unknown'));

-- Fast filtering by tier (e.g. "show me all network-capable tools")
CREATE INDEX IF NOT EXISTS idx_wasm_modules_capability_world
    ON wasm_modules (capability_world);

COMMENT ON COLUMN wasm_modules.capability_world IS
    'WIT capability world detected at compile time: minimal | network | trusted | unknown';
COMMENT ON COLUMN wasm_modules.imported_interfaces IS
    'talos:core/* WIT interface names imported by this component (byte-scan detected)';

-- Self-validate
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'wasm_modules' AND column_name = 'capability_world'
    ) THEN
        RAISE EXCEPTION 'Migration 014 failed: capability_world column not created';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'wasm_modules' AND column_name = 'imported_interfaces'
    ) THEN
        RAISE EXCEPTION 'Migration 014 failed: imported_interfaces column not created';
    END IF;

    RAISE NOTICE 'Migration 014 completed: capability_world + imported_interfaces added to wasm_modules';
END $$;
