-- Fix node_templates rows that were installed via install_module_from_catalog
-- before the category field was read from talos.json metadata.
-- The old code always stored category = 'catalog' as a placeholder.

UPDATE node_templates SET category = 'Network'
WHERE name = 'HTTP Request' AND category = 'catalog';

UPDATE node_templates SET category = 'Development'
WHERE name = 'Echo/Debug' AND category = 'catalog';
