-- RFC 0005 S3: provision `talos_app`, the non-superuser / non-BYPASSRLS
-- role that request-path transactions run as via `SET LOCAL ROLE`, so the
-- RFC 0004 RLS policies ENFORCE even when the controller's underlying
-- connection is a superuser (the common in-cluster Postgres deploy where
-- POSTGRES_USER is the bootstrap superuser, and RLS is silently bypassed
-- today — the boot guard warns about exactly this).
--
-- Model (operator-chosen): SET LOCAL ROLE, NOT a separate login role.
-- talos-db's begin_tenant_read_scoped / begin_org_scoped prepend
-- `SET LOCAL ROLE talos_app` to the per-tx GUC SET LOCALs WHEN
-- `TALOS_RLS_SET_ROLE` is set on the controller (default OFF). Because
-- SET LOCAL ROLE is transaction-scoped it resets on commit/rollback — no
-- pooled-connection leakage (same discipline as the GUC). Enforcement is
-- OFF until the operator flips the flag, so this migration is a runtime
-- no-op until then: it only creates the role and grants.
--
-- talos_app is NOLOGIN (reachable only via SET ROLE from the
-- authenticated controller session — same shape as talos_guest,
-- migration 20260522120000) and gets the full request-path DML grants.
-- Cross-cutting internal readers (engine graph-load, embeddings,
-- scheduler, analytics) do NOT SET ROLE — they stay on the underlying
-- owner/superuser connection and bypass RLS by design (the enumerated,
-- upstream-authorized escape hatch). A dedicated `talos_system`
-- BYPASSRLS role is deferred to the S3 step that needs an explicit
-- non-superuser reader — and to keep THIS migration portable to managed
-- Postgres (RDS/Neon), where granting BYPASSRLS requires a true
-- superuser the migration runner may not be.
--
-- CURRENT_USER (the migration runner = the controller's connecting role)
-- must hold CREATEROLE. If it doesn't in your environment, run the
-- CREATE ROLE block as a superuser first. Idempotent throughout.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_app') THEN
        CREATE ROLE talos_app
            NOLOGIN
            NOSUPERUSER
            NOBYPASSRLS
            NOCREATEDB
            NOCREATEROLE;
        COMMENT ON ROLE talos_app IS
            'RFC 0005 S3: request-path role. Reached via SET LOCAL ROLE from '
            'the controller session so RLS enforces under a superuser '
            'connection. See migrations/20260529220000_talos_app_role.sql.';
    END IF;
END$$;

-- Defensive re-assert (in case the role pre-existed, hand-created with
-- the wrong attributes). NOSUPERUSER + NOBYPASSRLS are the
-- security-critical ones: without them `SET ROLE talos_app` would still
-- bypass RLS and the whole mechanism would be a silent no-op.
ALTER ROLE talos_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- Membership so the controller session can `SET LOCAL ROLE talos_app`
-- (Postgres requires the session role to be a member of the target).
-- Idempotent: re-GRANT of an existing membership is a no-op (PG 14+).
DO $$
DECLARE app_role text := CURRENT_USER;
BEGIN
    IF app_role <> 'talos_app' THEN
        EXECUTE format('GRANT talos_app TO %I', app_role);
    END IF;
END$$;

-- Request-path privileges. talos_app is NOT the table owner (the
-- migration runner owns the tables), so a plain RLS ENABLE already
-- applies to it; the S0–S2 tables additionally use FORCE for the owner
-- path. These grants give talos_app the DML the request paths perform;
-- RLS scopes WHICH rows, the grant scopes the verbs.
GRANT USAGE ON SCHEMA public TO talos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO talos_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO talos_app;

-- Future tables/sequences created by the migration runner auto-grant to
-- talos_app, so new migrations don't need a manual GRANT (defends against
-- the "new table is silently inaccessible to talos_app" footgun that
-- would surface only once enforcement is flipped on).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO talos_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO talos_app;
