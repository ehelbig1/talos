-- Key versioning and rotation support for envelope encryption.
-- Allows transparent key rotation without decrypting all secrets at once.
--
-- NOTE: data_encryption_keys is created at runtime by SecretsManager, not by
-- migrations.  All ALTER TABLE statements are wrapped in DO blocks that check
-- for the table's existence first.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'data_encryption_keys') THEN
        ALTER TABLE data_encryption_keys
            ADD COLUMN IF NOT EXISTS key_version     INTEGER NOT NULL DEFAULT 1,
            ADD COLUMN IF NOT EXISTS created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            ADD COLUMN IF NOT EXISTS expires_at      TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS rotated_from    UUID;
    END IF;
END
$$;

-- Track which key version encrypted each secret for transparent re-encryption.
-- The secrets table IS created by migrations, so this is safe.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'secrets') THEN
        ALTER TABLE secrets
            ADD COLUMN IF NOT EXISTS key_version     INTEGER NOT NULL DEFAULT 1;
    END IF;
END
$$;

-- Key rotation audit trail.
CREATE TABLE IF NOT EXISTS key_rotation_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    old_key_version INTEGER NOT NULL,
    new_key_version INTEGER NOT NULL,
    rotated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_by      UUID,
    reason          TEXT,
    secrets_migrated INTEGER NOT NULL DEFAULT 0
);

-- Index for finding secrets that need re-encryption after rotation.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'secrets') THEN
        CREATE INDEX IF NOT EXISTS idx_secrets_key_version ON secrets (key_version);
    END IF;
END
$$;

-- Index for finding expired keys (created when data_encryption_keys exists).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'data_encryption_keys') THEN
        CREATE INDEX IF NOT EXISTS idx_dek_expires
            ON data_encryption_keys (expires_at)
            WHERE expires_at IS NOT NULL;
    END IF;
END
$$;
