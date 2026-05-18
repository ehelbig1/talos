-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    owner_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Organization members with roles
CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',  -- 'owner', 'admin', 'member', 'viewer'
    invited_by UUID,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, user_id)
);

-- Link workflows to organizations (optional - workflows can be personal or org-owned)
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);

-- Link modules to organizations
ALTER TABLE wasm_modules ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);

-- Link secrets to organizations
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);

CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org ON organization_members(org_id);
CREATE INDEX IF NOT EXISTS idx_workflows_org ON workflows(org_id) WHERE org_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_modules_org ON wasm_modules(org_id) WHERE org_id IS NOT NULL;
