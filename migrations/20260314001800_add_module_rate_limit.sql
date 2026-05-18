-- Add per-module outbound HTTP rate limiting columns
ALTER TABLE wasm_modules ADD COLUMN IF NOT EXISTS rate_limit_per_minute INTEGER;
ALTER TABLE node_templates ADD COLUMN IF NOT EXISTS rate_limit_per_minute INTEGER;
