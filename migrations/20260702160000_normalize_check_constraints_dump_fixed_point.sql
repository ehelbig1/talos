-- RFC 0009 (migration baseline): make two CHECK constraints pg_dump
-- round-trip FIXED POINTS.
--
-- `make verify-schema-baseline` diffs dump(full chain) against
-- dump(baseline snapshot + seed + tail). These two constraints were the
-- only difference: Postgres normalizes their expressions differently on
-- a SECOND parse (dump text re-parsed) than it did on the first (the
-- original migration text) — parenthesization and ARRAY-cast placement
-- only, zero semantic change. Recreating them from the once-normalized
-- text makes parse(text) dump back as the same text on both paths, so
-- the verifier can stay byte-exact instead of learning fuzzy matching.
--
-- Semantic no-op: same rules, same names. Idempotent via DO $$ guards.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'modules_integration_name_check'
          AND conrelid = 'modules'::regclass
    ) THEN
        ALTER TABLE modules DROP CONSTRAINT modules_integration_name_check;
    END IF;
    ALTER TABLE modules ADD CONSTRAINT modules_integration_name_check
        CHECK (((integration_name IS NULL) OR ((length(integration_name) >= 1) AND (length(integration_name) <= 64) AND (integration_name ~ '^[a-z0-9_-]+$'::text))));
EXCEPTION WHEN duplicate_object THEN
    NULL; -- re-run: constraint already in normalized form
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_org_members_role'
          AND conrelid = 'organization_members'::regclass
    ) THEN
        ALTER TABLE organization_members DROP CONSTRAINT chk_org_members_role;
    END IF;
    ALTER TABLE organization_members ADD CONSTRAINT chk_org_members_role
        CHECK (((role)::text = ANY (ARRAY[('owner'::character varying)::text, ('admin'::character varying)::text, ('member'::character varying)::text, ('viewer'::character varying)::text])));
EXCEPTION WHEN duplicate_object THEN
    NULL; -- re-run: constraint already in normalized form
END $$;
