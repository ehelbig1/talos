-- Add language column to wasm_modules to support JS/TS compilation
ALTER TABLE wasm_modules ADD COLUMN IF NOT EXISTS language VARCHAR(20) NOT NULL DEFAULT 'rust';
