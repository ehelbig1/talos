-- Add optional org_id to api_keys to scope keys to a specific organization.
-- When org_id IS NOT NULL, the key can only access resources within that org.
-- When org_id IS NULL, the key has access to all resources the user can access (legacy behavior).

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Index for looking up org-scoped keys
CREATE INDEX IF NOT EXISTS idx_api_keys_org_id ON api_keys(org_id) WHERE org_id IS NOT NULL;
