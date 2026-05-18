-- Clear the pre-baked WASM binary for Database Query so that the direct tool
-- JIT-recompiles from the updated template source (which now includes
-- get-last-error support for descriptive error messages).
-- The template seeder does NOT overwrite precompiled_wasm (it's excluded from
-- the ON CONFLICT UPDATE), so this must be done via migration.

UPDATE node_templates
SET precompiled_wasm = NULL
WHERE name = 'Database Query';
