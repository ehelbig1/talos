ALTER TABLE wasm_modules ADD COLUMN IF NOT EXISTS dependencies JSONB;
