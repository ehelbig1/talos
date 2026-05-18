-- Add missing foreign keys and CHECK constraint to organization_members.
-- These were omitted from the original 20260309000600_add_organizations migration.

-- Foreign key: organization_members.user_id -> users(id)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_org_members_user'
          AND table_name = 'organization_members'
    ) THEN
        ALTER TABLE organization_members
            ADD CONSTRAINT fk_org_members_user
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;

-- Foreign key: organization_members.invited_by -> users(id)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_org_members_invited_by'
          AND table_name = 'organization_members'
    ) THEN
        ALTER TABLE organization_members
            ADD CONSTRAINT fk_org_members_invited_by
            FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL;
    END IF;
END $$;

-- CHECK constraint: role must be one of the allowed values
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.check_constraints
        WHERE constraint_name = 'chk_org_members_role'
    ) THEN
        ALTER TABLE organization_members
            ADD CONSTRAINT chk_org_members_role
            CHECK (role IN ('owner', 'admin', 'member', 'viewer'));
    END IF;
END $$;
