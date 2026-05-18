-- BUG-39: text-analyzer template source was updated to read upstream input from
-- multiple locations (input.text, input.body, input.content, input.data).
-- wasm_modules rows compiled from the old template still have stale WASM bytes.
-- Deleting them forces the next compile_template call to recompile from the
-- updated code_template stored in node_templates.
DELETE FROM wasm_modules
WHERE template_id = (
    SELECT id FROM node_templates WHERE name = 'Text Analyzer' LIMIT 1
);
