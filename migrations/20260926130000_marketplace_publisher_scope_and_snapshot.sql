-- Marketplace listings: publisher-scoped identity + a frozen install snapshot.
--
-- (1) `UNIQUE (name, version)` carried no publisher, and the publish upsert's
--     conflict arm had no ownership predicate, so ANY user could overwrite
--     another publisher's listing (including a verified first-party one) —
--     and, publishing first, squat a name so the built-in republish failed on
--     the unique violation. The key is now `(publisher_id, name, version)`:
--     a listing can only ever conflict with its own publisher's row.
--
-- (2) Install read the publisher's CURRENT module row, so a hot_update after
--     publish reached every later installer. Publishing now freezes the code
--     and the non-secret grants on the listing; install reads the snapshot.
--     `allowed_secrets` is deliberately NOT snapshotted: secrets resolve as
--     the INSTALLER, who supplies their own grant (and the publisher's vault
--     paths can carry their user id / account address).
--
-- Existing user listings are frozen from their module row as it stands now
-- (no worse than before; the next change to the source no longer propagates).
-- System (first-party) listings keep resolving the live catalog row.

ALTER TABLE module_marketplace DROP CONSTRAINT IF EXISTS module_marketplace_name_version_key;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'module_marketplace_publisher_name_version_key'
    ) THEN
        ALTER TABLE module_marketplace
            ADD CONSTRAINT module_marketplace_publisher_name_version_key
            UNIQUE (publisher_id, name, version);
    END IF;
END $$;

ALTER TABLE module_marketplace
    ADD COLUMN IF NOT EXISTS snapshot_source_code TEXT,
    ADD COLUMN IF NOT EXISTS snapshot_wasm_bytes BYTEA,
    ADD COLUMN IF NOT EXISTS snapshot_config_schema JSONB,
    ADD COLUMN IF NOT EXISTS snapshot_allowed_hosts TEXT[],
    ADD COLUMN IF NOT EXISTS snapshot_allowed_methods TEXT[],
    ADD COLUMN IF NOT EXISTS snapshot_requires_approval_for TEXT[],
    ADD COLUMN IF NOT EXISTS snapshot_content_hash TEXT,
    ADD COLUMN IF NOT EXISTS snapshot_taken_at TIMESTAMPTZ;

UPDATE module_marketplace mm SET
    snapshot_source_code = m.source_code,
    snapshot_wasm_bytes = NULLIF(m.wasm_bytes, ''::bytea),
    snapshot_config_schema = m.config_schema,
    snapshot_allowed_hosts = m.allowed_hosts,
    snapshot_allowed_methods = m.allowed_methods,
    snapshot_requires_approval_for = m.requires_approval_for,
    snapshot_content_hash = m.content_hash,
    snapshot_taken_at = NOW()
FROM modules m
WHERE m.id = mm.module_id
  AND mm.publisher_id <> '00000000-0000-0000-0000-000000000000'::uuid
  AND mm.snapshot_taken_at IS NULL;
