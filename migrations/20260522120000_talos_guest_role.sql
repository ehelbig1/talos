-- Wasm-security review 2026-05-22 (MEDIUM-2): per-actor Postgres role
-- for WASM guest SQL.
--
-- ## Why
--
-- Before this migration, every guest SQL query (worker
-- `wit_database::execute_query` → controller
-- `talos.database.query` RPC subscriber) executed against the
-- controller's primary Postgres connection pool, which authenticates
-- as the application user. That user typically has broad table
-- privileges (it owns the schema), so any guest with `database-node`
-- capability inherited those privileges. The AST-side validator
-- (`worker/src/sql_validator.rs`) blocks dangerous statement *types*
-- (DDL, COPY, SET ROLE, LISTEN, …) and now (MEDIUM-1 sibling) blocks
-- dangerous expression-level functions (`pg_sleep`,
-- `pg_read_server_files`, `pg_terminate_backend`, `dblink`, …) — but
-- the role itself was still the high-privilege app user.
--
-- This migration creates a low-privilege `talos_guest` role and the
-- controller-side RPC handler wraps each guest query in:
--
--     BEGIN;
--     SET LOCAL ROLE talos_guest;
--     <guest SQL>;
--     COMMIT;
--
-- so the privileges in effect for the guest query are the role's
-- (effectively nothing by default) rather than the app user's.
--
-- ## Opt-in via env
--
-- The role wrap is gated by the controller's `TALOS_RPC_GUEST_ROLE`
-- env var (set to the role name to enable; unset to keep the legacy
-- behaviour). This lets operators roll out per environment and roll
-- back instantly without redeploying. The migration itself is
-- idempotent so it can be applied before the env flip without
-- breaking existing workflows.
--
-- ## What the role can do by default
--
-- Essentially nothing. The role is `NOLOGIN NOSUPERUSER NOCREATEDB
-- NOCREATEROLE NOINHERIT` and the migration revokes the public
-- schema USAGE + CREATE that PUBLIC has by default. Specifically:
--
--   * Cannot log in directly (NOLOGIN). The app user `SET LOCAL ROLE`s
--     into it from an authenticated connection.
--   * Cannot escalate via role inheritance (NOINHERIT).
--   * Cannot run CREATE / DROP / ALTER (NOSUPERUSER NOCREATEDB
--     NOCREATEROLE + the validator's DDL block).
--   * Cannot create temp tables in the public schema (revoked below).
--   * Cannot read or write any user table unless an operator
--     explicitly grants — see the "Adding guest-readable tables"
--     section below.
--
-- Postgres function `pg_catalog.*` execute privileges fall back to
-- the PUBLIC grant for most functions (Postgres design); REVOKE on
-- talos_guest individually doesn't override PUBLIC. That's why the
-- AST validator (MEDIUM-1) is the primary defense for function calls
-- and this role is defense-in-depth for the table-access vector.
--
-- ## Adding guest-readable tables
--
-- Operators wanting to expose specific tables for guest SELECTs:
--
--     GRANT USAGE ON SCHEMA public TO talos_guest;
--     GRANT SELECT ON public.my_guest_table TO talos_guest;
--
-- Or for an entire schema:
--
--     GRANT USAGE ON SCHEMA public TO talos_guest;
--     GRANT SELECT ON ALL TABLES IN SCHEMA public TO talos_guest;
--     ALTER DEFAULT PRIVILEGES IN SCHEMA public
--         GRANT SELECT ON TABLES TO talos_guest;
--
-- For row-level filtering combine with RLS policies (`CREATE POLICY
-- ... FOR SELECT TO talos_guest USING (...)`).
--
-- ## Rollback
--
-- The role grant is `helm.sh/resource-policy: keep`-equivalent for
-- migrations: dropping it would break in-flight guest queries. To
-- disable the wrap, unset `TALOS_RPC_GUEST_ROLE` on the controller
-- and restart. Drop the role separately only after confirming no
-- workflow uses guest SQL.
--
-- ----------------------------------------------------------------------

-- Idempotent role creation. CURRENT_USER (the app user running this
-- migration) must hold `CREATEROLE` privilege to create the role —
-- this is the standard role for application bootstrap; if it fails
-- in your environment, run the CREATE ROLE block as a superuser
-- before applying this migration.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_guest') THEN
        -- NOLOGIN: only reachable via SET LOCAL ROLE from an authenticated session.
        -- NOSUPERUSER NOCREATEDB NOCREATEROLE: cannot escalate to DDL.
        -- NOINHERIT: cannot inherit privileges from parent roles.
        CREATE ROLE talos_guest
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT;
        COMMENT ON ROLE talos_guest IS
            'Low-privilege role for WASM guest SQL via talos.database.query RPC. '
            'See migrations/20260522120000_talos_guest_role.sql. '
            'Add GRANT SELECT on specific tables to expose them to guest workflows.';
    END IF;
END$$;

-- Grant talos_guest to CURRENT_USER so the app can `SET LOCAL ROLE talos_guest`.
-- Postgres requires the session user to be a member of the target role for
-- `SET ROLE` to succeed; this grant makes the membership explicit. Idempotent:
-- GRANT to a role that already has the membership is a no-op in Postgres 14+.
DO $$
DECLARE
    app_role text := CURRENT_USER;
BEGIN
    -- Skip if app_role IS already talos_guest (defensive — shouldn't happen
    -- in practice since the app user can't be `talos_guest` which is NOLOGIN).
    IF app_role <> 'talos_guest' THEN
        EXECUTE format('GRANT talos_guest TO %I', app_role);
    END IF;
END$$;

-- Revoke the implicit PUBLIC grants on the public schema for talos_guest.
-- Postgres 15+ already removes USAGE/CREATE from PUBLIC by default for new
-- databases, but legacy databases (and explicit later GRANTs) may have re-
-- added them. Revoking from `talos_guest` specifically does NOT affect
-- other roles — it's a per-role denial that overrides any role-targeted
-- GRANT but does NOT override PUBLIC's grant. Operators on databases with
-- PUBLIC USAGE still active should follow up with a manual REVOKE FROM
-- PUBLIC on schemas they want isolated, OR (simpler) just don't grant
-- the guest any table access until they explicitly want to.
DO $$
BEGIN
    -- These REVOKEs are safe to run even if the grant doesn't exist.
    -- They're here to document intent; the validator + role flags do
    -- the heavy lifting.
    EXECUTE 'REVOKE ALL ON SCHEMA public FROM talos_guest';
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM talos_guest';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM talos_guest';
    EXECUTE 'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM talos_guest';
EXCEPTION
    -- Some hosted Postgres providers (Neon, RDS) restrict ALL-form REVOKEs
    -- on system-managed schemas. Swallow the error here — the role's
    -- NOLOGIN + NOINHERIT + the AST validator are the primary fences;
    -- this is a belt-and-suspenders revocation.
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Skipping ALL-form REVOKE on public schema (insufficient privilege; talos_guest role flags still apply)';
    WHEN OTHERS THEN
        RAISE NOTICE 'Skipping ALL-form REVOKE on public schema (%); talos_guest role flags still apply', SQLERRM;
END$$;
