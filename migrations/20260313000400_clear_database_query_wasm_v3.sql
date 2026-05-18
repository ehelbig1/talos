-- Clear Database Query pre-baked WASM (v3).
-- Template rewritten to use string concatenation instead of format!() with
-- literal braces (which Handlebars templating interpreted as expressions).

UPDATE node_templates
SET precompiled_wasm = NULL
WHERE name = 'Database Query';
