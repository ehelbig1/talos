-- Add FK on organizations.owner_id
ALTER TABLE organizations
ADD CONSTRAINT fk_organizations_owner
FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT;

-- Add FK on workflow_versions.published_by
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'workflow_versions' AND column_name = 'published_by') THEN
        ALTER TABLE workflow_versions
        ADD CONSTRAINT fk_workflow_versions_published_by
        FOREIGN KEY (published_by) REFERENCES users(id) ON DELETE RESTRICT;
    END IF;
END $$;

-- Add FK on workflow_schedules.user_id
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'workflow_schedules' AND column_name = 'user_id') THEN
        ALTER TABLE workflow_schedules
        ADD CONSTRAINT fk_workflow_schedules_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;
