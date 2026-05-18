-- Add missing indexes to improve query performance

-- Optimize session lookups (used on every authenticated request)
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id_expires_at ON user_sessions(user_id, expires_at);

-- Optimize workflow module reference lookups
CREATE INDEX IF NOT EXISTS idx_workflow_module_refs_workflow_id ON workflow_module_refs(workflow_id);

-- Optimize OAuth account lookups by provider and provider_user_id
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_user_id ON oauth_accounts(provider, provider_user_id);
