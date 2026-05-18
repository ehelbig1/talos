-- Clear the pre-baked WASM binary for Database Query (v2).
-- The template was rewritten to avoid serde_json::from_str/to_string inside WASM,
-- which caused linear memory exhaustion on result sets >100 rows.
-- The new template uses string interpolation instead, using ~1/3 the memory.

UPDATE node_templates
SET precompiled_wasm = NULL
WHERE name = 'Database Query';
