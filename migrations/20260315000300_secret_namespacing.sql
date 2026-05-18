-- Add namespace column for secret isolation
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS namespace TEXT NOT NULL DEFAULT 'default';

-- Update index to include namespace for scoped lookups
CREATE INDEX IF NOT EXISTS idx_secrets_namespace_keypath ON secrets(namespace, key_path);

-- Add namespace to the unique constraint on key_path
-- First drop existing unique constraint on key_path alone
ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_key_path_key;
-- Add new unique constraint scoped to namespace
ALTER TABLE secrets ADD CONSTRAINT secrets_namespace_key_path_unique UNIQUE (namespace, key_path);
