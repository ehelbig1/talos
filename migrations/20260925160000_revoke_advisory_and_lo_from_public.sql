-- Guest SQL must not reach the advisory-lock or large-object function
-- families. Revoke EXECUTE from PUBLIC; keep it for the roles the controller
-- itself runs as.
--
-- ## Why
--
-- Guest SQL (the `database` capability world → signed `talos.database.query`
-- RPC → `talos-rpc-subscribers::execute_guest_query`) runs on the
-- controller's SHARED app pool inside `BEGIN; [SET LOCAL ROLE talos_guest;]
-- <sql>; COMMIT`. Two function families leave state that boundary does not
-- clear:
--
--   * `pg_advisory_*` / `pg_try_advisory_*` — a SESSION-level lock
--     (`pg_advisory_lock(k)`) survives COMMIT and ROLLBACK, so the pooled
--     connection went back to the pool holding it. The controller takes its
--     own advisory locks on the same pool (budget admission, secret upsert,
--     the Google Calendar fleet lock), so a colliding key blocks those paths.
--   * `lo_*`, `loread`, `lowrite` — `lo_create` / `lo_from_bytea` / `lo_put` /
--     `lowrite` create rows in `pg_largeobject` that outlive the transaction
--     and every tenant boundary.
--
-- Migration 20260522120000 already notes why the role alone cannot close
-- this: Postgres grants EXECUTE on most `pg_catalog` functions to PUBLIC, and
-- a REVOKE aimed at `talos_guest` does not override a PUBLIC grant. So this
-- revokes from PUBLIC and re-grants to the roles that need the functions.
--
-- ## Three layers, and this is the third
--
--   1. The expression deny-list
--      (`talos_workflow_job_protocol::is_disallowed_sql_function`) refuses
--      both families by name PREFIX, on the worker AND the controller.
--   2. `execute_guest_query` runs `pg_advisory_unlock_all()` on the
--      connection after every guest transaction and closes it instead of
--      returning it to the pool when it cannot (timeout, failed unlock).
--   3. This migration: with `TALOS_RPC_GUEST_ROLE=talos_guest`, Postgres
--      itself refuses the call.
--
-- Layer 3 binds only when the guest role fence is ON. With it unset (the
-- default outside production), guest SQL runs as the app role, which keeps
-- EXECUTE below, and layers 1–2 are the controls.
--
-- ## Who keeps EXECUTE
--
--   * CURRENT_USER — the migration runner, which in every shipped deployment
--     (compose `migrate`, the chart's migrations Job) connects with the SAME
--     `DATABASE_URL` as the controller. Same assumption 20260522120000 and
--     20260529220000 make. A deployment that migrates as one role and runs as
--     another must GRANT EXECUTE on these functions to the runtime role
--     itself, unless that role is a member of `talos_app` (it then inherits).
--   * `talos_app`, if it exists — REQUIRED, not defensive: with
--     `TALOS_RLS_SET_ROLE` on, `SecretsManager::upsert_secret` takes
--     `pg_advisory_xact_lock` inside `begin_org_scoped` / `begin_user_scoped`,
--     i.e. AFTER `SET LOCAL ROLE talos_app`.
--
-- Only functions PUBLIC can execute TODAY are touched, so this RESTORES what
-- PUBLIC had and never widens: `lo_import` / `lo_export` (server filesystem
-- I/O, owner-only by default) are left exactly as they are. That filter is
-- also what makes the migration idempotent — a second run finds nothing
-- PUBLIC can execute and does nothing.
--
-- ## Managed Postgres (RDS, Neon, Cloud SQL)
--
-- The runner there is not the owner of `pg_catalog` functions and is not a
-- superuser, so Postgres answers the GRANT/REVOKE with a WARNING ("no
-- privileges could be revoked") and changes nothing. On such a deployment
-- this migration is a NO-OP and layers 1–2 are the controls. Each function is
-- handled in its own sub-block so an outright refusal on one cannot fail the
-- migration, and the closing NOTICE counts what PUBLIC can still execute.
--
-- Deliberately NOT a general function allowlist for guest SQL: guest SQL is
-- caller-authored at runtime and its population cannot be measured (0 guest
-- statements in `pg_stat_statements`, 0 executions of either database-world
-- module on the reference deployment), so an allowlist's blast radius would
-- be a guess.

DO $$
DECLARE
    fn regprocedure;
    has_app_role boolean := EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_app');
    has_guest_role boolean := EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_guest');
    still_public integer;
BEGIN
    FOR fn IN
        SELECT p.oid::regprocedure
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'pg_catalog'
           AND (p.proname LIKE 'pg\_advisory\_%'
                OR p.proname LIKE 'pg\_try\_advisory\_%'
                OR p.proname LIKE 'lo\_%'
                OR p.proname IN ('loread', 'lowrite'))
           AND EXISTS (
                SELECT 1
                  FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
                 WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')
         ORDER BY 1
    LOOP
        -- Grants first, revoke last, in one sub-block: if a grant raises, the
        -- block's savepoint undoes it and PUBLIC keeps EXECUTE, so no role the
        -- controller runs as can lose a function it had.
        BEGIN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', fn, CURRENT_USER::text);
            IF has_app_role AND CURRENT_USER::text <> 'talos_app' THEN
                EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO talos_app', fn);
            END IF;
            EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', fn);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Skipping EXECUTE revoke on % (%); the SQL validator deny-list and the controller''s unlock backstop still apply', fn, SQLERRM;
        END;
    END LOOP;

    -- A DIRECT grant to talos_guest would survive the PUBLIC revoke. None is
    -- made by any migration; this clears a hand-made one. The whole family,
    -- including lo_import / lo_export.
    IF has_guest_role THEN
        FOR fn IN
            SELECT p.oid::regprocedure
              FROM pg_proc p
              JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'pg_catalog'
               AND (p.proname LIKE 'pg\_advisory\_%'
                    OR p.proname LIKE 'pg\_try\_advisory\_%'
                    OR p.proname LIKE 'lo\_%'
                    OR p.proname IN ('loread', 'lowrite'))
             ORDER BY 1
        LOOP
            BEGIN
                EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM talos_guest', fn);
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'Skipping talos_guest revoke on % (%)', fn, SQLERRM;
            END;
        END LOOP;
    END IF;

    SELECT count(*) INTO still_public
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'pg_catalog'
       AND (p.proname LIKE 'pg\_advisory\_%'
            OR p.proname LIKE 'pg\_try\_advisory\_%'
            OR p.proname LIKE 'lo\_%'
            OR p.proname IN ('loread', 'lowrite'))
       AND EXISTS (
            SELECT 1
              FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
             WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE');
    IF still_public > 0 THEN
        RAISE NOTICE 'PUBLIC can still EXECUTE % advisory-lock / large-object function(s): this role does not own pg_catalog, so the revoke was a no-op here; the SQL validator deny-list and the controller''s unlock backstop are the controls', still_public;
    END IF;
END$$;
