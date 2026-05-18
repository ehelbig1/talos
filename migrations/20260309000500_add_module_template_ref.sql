-- Add columns to track which visual template and config were used to create a module.
-- This allows re-editing template-based modules by loading the original config.
ALTER TABLE wasm_modules ADD COLUMN IF NOT EXISTS template_config JSONB;
ALTER TABLE wasm_modules ADD COLUMN IF NOT EXISTS source_template_id VARCHAR(64);
