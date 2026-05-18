-- Add indexes for API key lookup performance and uniqueness on active keys.
-- Regular index for fast prefix lookup.
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys (key_prefix);

-- Unique index to ensure at most one active key per prefix (helps prevent collisions).
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_key_prefix_active ON api_keys (key_prefix)
WHERE is_active = true;

-- End of migration.
