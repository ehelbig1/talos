ALTER TABLE wasm_modules
    DROP CONSTRAINT IF EXISTS wasm_modules_capability_world_check;

ALTER TABLE wasm_modules
    ADD CONSTRAINT wasm_modules_capability_world_check
    CHECK (capability_world IN ('minimal', 'network', 'secrets', 'filesystem', 'messaging', 'cache', 'database', 'trusted', 'unknown'));

COMMENT ON COLUMN wasm_modules.capability_world IS
    'WIT capability world detected at compile time: minimal | network | secrets | filesystem | messaging | cache | database | trusted | unknown';

DO $$
BEGIN
    RAISE NOTICE 'Migration 016 completed: expanded capability_world values added to wasm_modules';
END $$;
