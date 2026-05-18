-- Clear Redis Cache pre-baked WASM (v2) — template now searches upstream
-- node outputs for value field at any nesting level.

UPDATE node_templates SET precompiled_wasm = NULL WHERE name = 'Redis Cache';
