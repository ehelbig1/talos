-- Add a dedicated allowed_hosts column to node_templates.
-- Previously, allowed_hosts was smuggled inside config_schema as the
-- "talos_allowed_hosts" JSON key, which is fragile, not queryable, and
-- pollutes the user-facing config schema.

ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS allowed_hosts TEXT[] NOT NULL DEFAULT '{}';

-- Back-fill from the legacy config_schema.talos_allowed_hosts JSON key
UPDATE node_templates
SET allowed_hosts = ARRAY(
    SELECT jsonb_array_elements_text(config_schema -> 'talos_allowed_hosts')
)
WHERE config_schema ? 'talos_allowed_hosts'
  AND allowed_hosts = '{}';

-- Remove the legacy key from config_schema so it no longer pollutes the
-- user-facing schema (e.g. frontend config forms).
UPDATE node_templates
SET config_schema = config_schema - 'talos_allowed_hosts'
WHERE config_schema ? 'talos_allowed_hosts';
