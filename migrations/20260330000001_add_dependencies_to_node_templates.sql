-- Add dependencies column to node_templates so custom sandbox templates
-- can store the third-party crate manifest used during compilation.
-- compile_template reads this column to re-inject deps into the Cargo workspace.
ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS dependencies JSONB;
