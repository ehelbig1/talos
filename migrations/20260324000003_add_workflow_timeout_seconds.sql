-- Add timeout_seconds column to workflows table.
-- This column was referenced in the create_workflow INSERT but was never added
-- via a migration, causing all create_workflow calls to fail on fresh deployments.
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS timeout_seconds INTEGER;
