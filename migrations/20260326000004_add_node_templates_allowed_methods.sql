ALTER TABLE node_templates
  ADD COLUMN IF NOT EXISTS allowed_methods TEXT[] DEFAULT '{}';
