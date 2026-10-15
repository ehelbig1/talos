-- The row-security backstop for the tenant tables a scoped transaction reads
-- (security review 2026-10-14, D-1).
--
-- Measured on the reference deployment before this was written (read-only):
--   * actor_memory: 52 rows, every one with an org_id equal to its actor's.
--     The table HAS had a policy since 20260719120000 (created inside a DO
--     loop, which is why a grep for `ALTER TABLE actor_memory ENABLE` finds
--     none), keyed on org_id with an `org_id IS NULL -> permit` arm that
--     20260912140000 retired on its siblings but not here. 0 rows take that
--     arm today; it is latent. The policy below derives the tenant from the
--     PARENT actor, the 20260912130000 shape: under talos_app the EXISTS is
--     itself filtered by `actors_tenant_isolation`, so a memory row is
--     visible exactly when its actor is.
--   * plaid_items, google_health_integrations, microsoft_365_integrations,
--     google_calendar_write_integrations, google_cloud_integrations: no
--     policy. Each has a `user_id` and an index leading with it. Their
--     readers that know the user (the cross-provider connection listing and
--     disconnect) now run in `begin_user_scoped`, so these policies are
--     evaluated, not decorative.
--
-- Deliberately left out (recorded in DECISIONS.md): memory_read_grants and
-- workflow_action_tokens (a token is presented before any user is known; the
-- owner is re-joined in the statement), atlassian_webhook_registrations and
-- github_app_installations (a provider delivery is read before its user is
-- known).
--
-- Every policy keeps the `GUC unset -> permit` arm of its siblings: a path
-- with no tenant context (engine, signed RPC, the superuser pool) is
-- unchanged. FORCE so the policy binds the table owner too.

ALTER TABLE actor_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE actor_memory FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_memory_tenant_isolation ON actor_memory;
CREATE POLICY actor_memory_tenant_isolation ON actor_memory
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM actors a WHERE a.id = actor_memory.actor_id)
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR EXISTS (SELECT 1 FROM actors a WHERE a.id = actor_memory.actor_id)
);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'plaid_items',
        'google_health_integrations',
        'microsoft_365_integrations',
        'google_calendar_write_integrations',
        'google_cloud_integrations'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I'
            || ' USING ('
            || '   NULLIF(current_setting(''app.current_user_id'', true), '''') IS NULL'
            || '   OR user_id = NULLIF(current_setting(''app.current_user_id'', true), '''')::uuid'
            || ' )'
            || ' WITH CHECK ('
            || '   NULLIF(current_setting(''app.current_user_id'', true), '''') IS NULL'
            || '   OR user_id = NULLIF(current_setting(''app.current_user_id'', true), '''')::uuid'
            || ' )',
            t || '_tenant_isolation', t
        );
    END LOOP;
END $$;
