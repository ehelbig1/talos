-- Performance index for the batch capability_world lookup query
-- used in MCP handle_tools_list and handle_tools_call.
-- Supports: SELECT DISTINCT ON (template_id) ... FROM wasm_modules
--           WHERE template_id = ANY($1) ORDER BY template_id, compiled_at DESC
CREATE INDEX IF NOT EXISTS idx_wasm_modules_template_compiled
ON wasm_modules(template_id, compiled_at DESC);
