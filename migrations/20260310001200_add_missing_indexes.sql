-- Migration: Add missing composite indexes for common query patterns
--
-- These indexes target hot query paths that currently require sequential scans
-- or use suboptimal single-column indexes:
--
-- 1. idx_workflow_executions_workflow_user   - "list executions for a given workflow by user"
-- 2. idx_workflow_executions_created_desc    - "recent executions" sorted by creation time
-- 3. idx_module_executions_module_created    - "execution history for a module" (uses started_at
--    since module_executions has no created_at column)
-- 4. idx_secrets_user_name                  - "list/lookup secrets by user and name"
-- 5. idx_integration_credentials_user_provider - "credential lookups by user + provider"
--    (complements the existing partial index from migration 021 which only covers is_active = TRUE)

-- 1. Composite index for filtering workflow executions by workflow + user
CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow_user
    ON workflow_executions(workflow_id, user_id);

-- 2. Index for "most recent executions" queries ordered by created_at
CREATE INDEX IF NOT EXISTS idx_workflow_executions_created_desc
    ON workflow_executions(created_at DESC);

-- 3. Composite index for module execution history
--    Note: module_executions uses started_at, not created_at
CREATE INDEX IF NOT EXISTS idx_module_executions_module_created
    ON module_executions(module_id, started_at DESC);

-- 4. Composite index for looking up secrets by user + name
CREATE INDEX IF NOT EXISTS idx_secrets_user_name
    ON secrets(user_id, name);

-- 5. Non-partial composite index for credential lookups (covers all rows,
--    unlike idx_integration_credentials_user_provider_active which is partial)
CREATE INDEX IF NOT EXISTS idx_integration_credentials_user_provider
    ON integration_credentials(user_id, provider, is_active);
