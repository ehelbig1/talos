-- pg_stat_statements — created WHERE THE SERVER CAN CARRY IT, a NOTICE where
-- it cannot (2026-09-08).
--
-- Package 33 measured what this platform can say about its own cost: nothing
-- per statement. `/metrics/prometheus` carried no per-tool series, the
-- controller log carried no per-call line, and `SHOW shared_preload_libraries`
-- on the dev server returns the EMPTY STRING — so `pg_stat_statements` is
-- AVAILABLE (`pg_available_extensions` lists it; the pgvector image ships the
-- contrib set) and cannot function. Every per-statement number in that
-- package's notes had to be counted CLIENT-side, from sqlx's own
-- `sqlx::query` tracing events, because the server had nothing to ask.
--
-- ## The guard, and the assumption it was written on that turned out FALSE
--
-- The obvious guard is "catch the error `CREATE EXTENSION` raises when the
-- library is not preloaded". Measured on this stack (PostgreSQL 17.10, no
-- preload) before it was written: **there is no such error.**
-- `CREATE EXTENSION pg_stat_statements` SUCCEEDS on a server that has not
-- preloaded the library. What fails is the first READ —
-- `SELECT count(*) FROM pg_stat_statements` answers
-- `ERROR: pg_stat_statements must be loaded via "shared_preload_libraries"` —
-- so an unguarded migration leaves every such deployment carrying an
-- extension whose only view raises on every query. Not destructive, but a
-- catalog entry that lies about a working instrument, which is the class this
-- repository spends most of its time removing.
--
-- So the gate is on the GUC itself, read from `current_setting`, and the
-- migration is a true no-op where the preload is absent. The measured SECOND
-- failure mode is kept in an EXCEPTION block rather than assumed away: the
-- extension is NOT `trusted`, so a non-superuser migration role gets
-- `ERROR: permission denied to create extension "pg_stat_statements" /
-- HINT: Must be superuser` — measured, with a plain LOGIN role. Managed
-- Postgres commonly runs migrations as exactly such a role, and a migration
-- that ERRORS there is strictly worse than the missing extension: it stops the
-- whole chain, including every migration after it.
--
-- The nested BEGIN/EXCEPTION is load-bearing and is the idiom CLAUDE.md's
-- migration rules already name: it opens an implicit SAVEPOINT, so a caught
-- error rolls back only the CREATE and the surrounding transaction survives. A
-- bare `DO $$ ... EXCEPTION $$` at the outer level would catch the error and
-- roll the whole migration back, silently.
--
-- ## Where the preload comes from, and where it deliberately does not
--
-- DEV gets it from `docker-compose.yml`'s postgres `command:`. THE HELM CHART
-- IS DELIBERATELY NOT CHANGED, and the cost is why: `shared_preload_libraries`
-- is a POSTMASTER-level GUC, so adding it to the in-cluster Postgres ConfigMap
-- takes effect only on a server RESTART — on the single-replica StatefulSet in
-- `deploy/helm/talos/templates/postgres/` that is a full database outage for
-- the length of a pod restart — and the extension itself takes a fixed shared
-- memory allocation (`pg_stat_statements.max` × ~1 KB, default 5 000 entries)
-- out of a deployment tuned in that chart for a 4 GiB VM. That is an
-- operator's decision to make deliberately, not a side effect of a migration.
--
-- Nothing in the application reads this extension. It is an operator
-- instrument: `SELECT query, calls, total_exec_time FROM pg_stat_statements`.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_available_extensions WHERE name = 'pg_stat_statements'
    ) THEN
        RAISE NOTICE 'pg_stat_statements is not available on this server (no contrib package); skipping.';
        RETURN;
    END IF;

    -- The GUC, not the CREATE, is the real test — see the header. `strpos`
    -- rather than an exact match: the setting is a comma-separated list and
    -- another library may legitimately share it.
    IF strpos(current_setting('shared_preload_libraries'), 'pg_stat_statements') = 0 THEN
        RAISE NOTICE 'pg_stat_statements is not in shared_preload_libraries; skipping. Creating it here would leave an extension whose only view raises on every read. Add shared_preload_libraries=pg_stat_statements and RESTART Postgres to enable it.';
        RETURN;
    END IF;

    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
        RAISE NOTICE 'pg_stat_statements is enabled.';
    EXCEPTION WHEN OTHERS THEN
        -- Measured shape: a non-superuser migration role. The extension is not
        -- `trusted`, so ownership of the database is not enough.
        RAISE NOTICE 'pg_stat_statements could not be created (%); the server is unchanged.', SQLERRM;
    END;
END
$$;
