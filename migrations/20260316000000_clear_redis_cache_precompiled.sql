-- Clear pre-baked WASM for Redis Cache template so JIT recompiles
-- from the updated template source (which now reads value from upstream input).

UPDATE node_templates
SET precompiled_wasm = NULL
WHERE name = 'Redis Cache';
