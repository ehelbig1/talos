-- Add 'automation' to System Administrator capabilities.
-- This was missing from the original seed, causing automation-node
-- sandbox compilation to be rejected by the RBAC check.

UPDATE agent_roles
SET allowed_capabilities = array_append(allowed_capabilities, 'automation')
WHERE name = 'System Administrator'
  AND NOT ('automation' = ANY(allowed_capabilities));
