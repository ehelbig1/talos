-- Add optional JSON Schema columns to node_templates for edge validation.
-- These are used by the engine to warn (not block) when connected nodes have
-- incompatible input/output schemas.
ALTER TABLE node_templates ADD COLUMN IF NOT EXISTS input_schema JSONB;
ALTER TABLE node_templates ADD COLUMN IF NOT EXISTS output_schema JSONB;
