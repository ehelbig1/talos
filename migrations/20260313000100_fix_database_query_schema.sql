-- Fix Database Query template config_schema to use lowercase field names.
-- The Rust struct uses lowercase `query` and `params` (no serde rename),
-- but the original schema declared uppercase QUERY/PARAMS.
-- This migration ensures the schema matches regardless of template seeding.

UPDATE node_templates
SET config_schema = '{"type": "object", "required": ["query"], "properties": {"query": {"type": "string", "description": "The SQL query to execute (use $1, $2, etc. for parameters)"}, "params": {"type": "array", "items": {"type": "string"}, "description": "Array of parameters to bind to the query"}}}'::jsonb
WHERE name = 'Database Query';
