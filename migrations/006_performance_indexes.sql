-- Migration 006: Performance and Security Indexes
-- Composite indexes for common query patterns and performance optimization

-- ============================================================================
-- SECURITY & PERFORMANCE - COMPOSITE INDEXES
-- ============================================================================

-- Secrets: User and key path lookup (common in workflow execution)
CREATE INDEX idx_secrets_user_keypath ON secrets(user_id, key_path);

-- Webhook listeners: Enabled listeners by user
CREATE INDEX idx_webhook_listeners_enabled_user ON webhook_listeners(id, enabled, user_id) WHERE enabled = true;

-- OAuth state tokens: State validation with expiry check
CREATE INDEX idx_oauth_state_tokens_state_expires ON oauth_state_tokens(state_token, expires_at);

-- ============================================================================
-- ADDITIONAL USEFUL INDEXES
-- ============================================================================

-- WASM modules: Find by template and user
CREATE INDEX idx_wasm_modules_template_user ON wasm_modules(template_id, user_id);

-- Workflows: Recent workflows by user
CREATE INDEX idx_workflows_user_created ON workflows(user_id, created_at DESC);

-- API keys: Active keys by user for listing
CREATE INDEX idx_api_keys_user_active ON api_keys(user_id, is_active) WHERE is_active = true;

-- Secrets: Recent access tracking
CREATE INDEX idx_secrets_last_accessed ON secrets(last_accessed_at DESC NULLS LAST);

-- Webhook listeners: Last triggered tracking
CREATE INDEX idx_webhook_listeners_last_triggered ON webhook_listeners(last_triggered_at DESC NULLS LAST);

-- User sessions: Active sessions (index all, filter at query time)
CREATE INDEX idx_user_sessions_user_expires ON user_sessions(user_id, expires_at);

-- OAuth accounts: Active accounts by provider
CREATE INDEX idx_oauth_accounts_provider_active ON oauth_accounts(provider, user_id);
