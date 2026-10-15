-- A '*' secret grant grants nothing, and no row holds one (operator decision
-- D2-D, 2026-10-15; security review C-8). `allowed_secrets = ['*']` delivered
-- every secret the module's user can read — every OAuth access token
-- included — into each dispatch's envelope. Every writer refuses it in code
-- (`talos_capability_world::refuse_wildcard_grant`,
-- `talos_registry::validate_allowed_secrets`); this constraint is the backstop
-- for a writer that does not ask. A module that held '*' keeps its other
-- entries and loses the wildcard: it reads nothing it does not name, and its
-- owner grants the exact paths (`update_module_secrets`). Measured on the
-- reference stack before this migration: 0 rows held '*'.
--
-- One statement per column, per row: `array_remove` keeps every other entry.
UPDATE modules SET allowed_secrets = array_remove(allowed_secrets, '*')
    WHERE '*' = ANY(allowed_secrets);
UPDATE modules SET owner_added_secrets = array_remove(owner_added_secrets, '*')
    WHERE '*' = ANY(owner_added_secrets);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'modules_no_star_secret_grant'
          AND conrelid = 'public.modules'::regclass
    ) THEN
        ALTER TABLE modules ADD CONSTRAINT modules_no_star_secret_grant CHECK (
            NOT ('*' = ANY(COALESCE(allowed_secrets, '{}'::text[])))
            AND NOT ('*' = ANY(COALESCE(owner_added_secrets, '{}'::text[])))
        );
    END IF;
END
$$;
