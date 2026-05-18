-- Add 'archived' as a valid agent status (softer than terminated: no cascade cleanup).
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_status_check;
ALTER TABLE agents ADD CONSTRAINT agents_status_check
    CHECK (status IN ('active', 'suspended', 'terminated', 'archived'));
