# One SQL statement per line. `#` starts a comment line; blank lines are skipped.
# Every table, column and value here is made up.
#
# This is the corpus the three SQL gates are pinned against:
#   classify.snapshot    talos_sql_classify::classify
#   worker.snapshot      talos_worker_runtime::sql_validator::validate_sql_with_policy
#   controller.snapshot  the controller's admission functions (talos-rpc-subscribers)
# A sqlparser bump that changes any verdict changes a snapshot line, and the
# change is reviewed. Add a line here, then re-bless (see the README beside this file).

# --- reads -------------------------------------------------------------------
SELECT 1
SELECT 1;
select a, b from t where id = $1
SELECT * FROM users WHERE id = $1 AND org_id = $2
SELECT DISTINCT a FROM t
SELECT DISTINCT ON (a) a, b FROM t ORDER BY a, b DESC
SELECT a AS x, count(*) FROM t GROUP BY a HAVING count(*) > 1
SELECT a FROM t ORDER BY a NULLS LAST LIMIT 10 OFFSET 5
SELECT a FROM t FETCH FIRST 5 ROWS ONLY
SELECT * FROM t JOIN u ON t.id = u.t_id LEFT JOIN v USING (id)
SELECT * FROM t CROSS JOIN u
SELECT * FROM t NATURAL JOIN u
SELECT * FROM t, LATERAL (SELECT * FROM u WHERE u.t_id = t.id) x
SELECT * FROM (SELECT 1) x
SELECT * FROM t WHERE id IN (SELECT id FROM u)
SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id = t.id)
SELECT * FROM t WHERE id = ANY($1)
SELECT (SELECT max(a) FROM u) AS m FROM t
SELECT * FROM t UNION SELECT * FROM u
SELECT * FROM t UNION ALL SELECT * FROM u INTERSECT SELECT * FROM v
SELECT * FROM t EXCEPT SELECT * FROM u
(SELECT 1) UNION (SELECT 2)
WITH a AS (SELECT 1) SELECT * FROM a
WITH a AS (SELECT 1), b AS (SELECT * FROM a) SELECT * FROM b
WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT n FROM r
WITH a AS MATERIALIZED (SELECT 1) SELECT * FROM a
WITH a AS NOT MATERIALIZED (SELECT 1) SELECT * FROM a
SELECT * FROM (WITH a AS (SELECT 1) SELECT * FROM a) x
VALUES (1, 'a'), (2, 'b')
TABLE t
SELECT * FROM t FOR UPDATE
SELECT * FROM t FOR SHARE SKIP LOCKED
SELECT * FROM t FOR NO KEY UPDATE NOWAIT
SELECT row_number() OVER (PARTITION BY a ORDER BY b) FROM t
SELECT sum(a) FILTER (WHERE b > 0) FROM t
SELECT a::text, CAST(b AS integer) FROM t
SELECT CASE WHEN a > 0 THEN 'p' ELSE 'n' END FROM t
SELECT data->>'k', data->'a'->0, data @> '{"k":1}' FROM t
SELECT data #>> '{a,b}' FROM t
SELECT ARRAY[1,2,3], a[1] FROM t
SELECT * FROM t WHERE name ILIKE $1
SELECT * FROM t WHERE name ~* 'x'
SELECT * FROM t WHERE created_at > now() - interval '1 day'
SELECT created_at AT TIME ZONE 'UTC' FROM t
SELECT coalesce(a, 0), nullif(b, ''), greatest(a, b) FROM t
SELECT extract(epoch FROM created_at) FROM t
SELECT * FROM generate_series(1, 10) g
SELECT * FROM unnest($1::int[]) AS x(id)
SELECT * FROM jsonb_to_recordset($1) AS x(a int, b text)
SELECT * FROM t TABLESAMPLE BERNOULLI (10)
SELECT a, b, sum(c) FROM t GROUP BY GROUPING SETS ((a), (b), ())
SELECT a, sum(c) FROM t GROUP BY ROLLUP (a)
SELECT * FROM t WHERE (a, b) IN ((1, 2), (3, 4))
SELECT * FROM t WHERE a BETWEEN 1 AND 2 AND b IS NOT NULL AND c IS DISTINCT FROM d
SELECT 'it''s', E'a\nb', $$dollar$$, $tag$tagged$tag$
SELECT "quoted col" FROM "Quoted Table"
SELECT * FROM public.t
SELECT * FROM a.b.c
SELECT count(*) FROM t WHERE tsv @@ to_tsquery('x')
SELECT * FROM t ORDER BY embedding <-> $1 LIMIT 5
SELECT now(), current_user, current_setting('x')
SELECT nextval('s')
SELECT setval('s', 1)
SELECT /* comment */ 1
SELECT 1 -- trailing comment
SELECT ';'
SELECT $$;$$
SELECT 1 /* outer /* nested */ still comment */
SELECT * FROM t WHERE a = 'x' /*! not mysql */
SELECT * INTO new_table FROM t
SELECT * INTO TEMP new_table FROM t
SELECT a FROM t WINDOW w AS (ORDER BY a)
SELECT * FROM t WHERE a = ALL (SELECT b FROM u)
SELECT * FROM ONLY t
SELECT * FROM t AS x (a, b)
SELECT * FROM ROWS FROM (generate_series(1, 2), generate_series(1, 3)) AS x(a, b)
SELECT * FROM t LIMIT ALL
SELECT * EXCLUDE (a) FROM t
FROM t SELECT a
SELECT * FROM t |> WHERE a > 1
SELECT 1 WHERE 1 = 1 UNION SELECT 2 ORDER BY 1

# --- mutations at the root ---------------------------------------------------
INSERT INTO t (a) VALUES ($1)
INSERT INTO t (a, b) VALUES (1, 2), (3, 4) RETURNING id
INSERT INTO t DEFAULT VALUES
INSERT INTO t (a) SELECT a FROM u
INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO NOTHING
INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b RETURNING *
INSERT INTO t AS x (a) VALUES (1)
INSERT INTO t (a) TABLE u
UPDATE t SET a = 1 WHERE id = $1
UPDATE t SET a = 1 WHERE id = $1 RETURNING a
UPDATE t SET a = u.a FROM u WHERE t.id = u.id
UPDATE t AS x SET a = 1
UPDATE ONLY t SET a = 1
UPDATE t SET (a, b) = (1, 2)
UPDATE t SET a = (SELECT max(a) FROM u)
DELETE FROM t WHERE id = $1
DELETE FROM t WHERE id = $1 RETURNING *
DELETE FROM t USING u WHERE t.id = u.id
DELETE FROM ONLY t
DELETE FROM t
MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN UPDATE SET a = 1
MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN DELETE
MERGE INTO t USING u ON t.a = u.a WHEN NOT MATCHED THEN INSERT (a) VALUES (u.a)
MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN UPDATE SET a = 1 RETURNING t.a
WITH a AS (SELECT 1 AS x) INSERT INTO t (a) SELECT x FROM a
WITH a AS (SELECT 1 AS x) UPDATE t SET a = (SELECT x FROM a)
WITH a AS (SELECT 1 AS x) INSERT INTO t (a) SELECT x FROM a RETURNING a
WITH a AS (SELECT 1 AS x) UPDATE t SET a = (SELECT x FROM a) RETURNING a
WITH a AS (SELECT 1 AS x) DELETE FROM t WHERE a IN (SELECT x FROM a)
WITH a AS (SELECT 1 AS x) MERGE INTO t USING a ON t.a = a.x WHEN MATCHED THEN DELETE

# --- a mutation carried by a query -------------------------------------------
WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins
WITH ins AS (INSERT INTO t (a) VALUES (1)) SELECT 1
WITH upd AS (UPDATE t SET a = 1 RETURNING a) SELECT * FROM upd
WITH upd AS (UPDATE t SET a = 1 WHERE id = $1) SELECT 1
WITH del AS (DELETE FROM t RETURNING a) SELECT * FROM del
WITH del AS (DELETE FROM t WHERE id = $1) SELECT 1
WITH m AS (MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN DELETE RETURNING t.a) SELECT * FROM m
WITH a AS (SELECT 1), ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM a
WITH a AS (SELECT 1), del AS (DELETE FROM t RETURNING a) SELECT * FROM a
WITH RECURSIVE ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins
WITH ins AS MATERIALIZED (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins
SELECT * FROM (WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins) x
SELECT * FROM (WITH del AS (DELETE FROM t RETURNING a) SELECT * FROM del) x
SELECT * FROM t WHERE id IN (WITH ins AS (INSERT INTO u (a) VALUES (1) RETURNING a) SELECT a FROM ins)
SELECT (WITH ins AS (INSERT INTO u (a) VALUES (1) RETURNING a) SELECT a FROM ins)
SELECT 1 UNION (WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins)
WITH outer_cte AS (WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins) SELECT * FROM outer_cte
WITH outer_cte AS (WITH del AS (DELETE FROM t RETURNING a) SELECT * FROM del) SELECT * FROM outer_cte
SELECT * FROM t JOIN (WITH upd AS (UPDATE u SET a = 1 RETURNING a) SELECT * FROM upd) x ON true
SELECT * FROM t, LATERAL (WITH ins AS (INSERT INTO u (a) VALUES (t.a) RETURNING a) SELECT * FROM ins) x
SELECT * FROM (INSERT INTO t (a) VALUES (1) RETURNING a) x
SELECT * FROM (UPDATE t SET a = 1 RETURNING a) x
SELECT * FROM (DELETE FROM t RETURNING a) x
SELECT * FROM t WHERE a IN (DELETE FROM u RETURNING a)
(INSERT INTO t (a) VALUES (1) RETURNING a)
(DELETE FROM t RETURNING a)
WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) INSERT INTO u (a) SELECT a FROM ins
WITH del AS (DELETE FROM t RETURNING a) INSERT INTO u (a) SELECT a FROM del
WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) VALUES (1)
WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) TABLE ins
SELECT * FROM t WHERE EXISTS (WITH upd AS (UPDATE u SET a = 1 RETURNING a) SELECT 1 FROM upd)
SELECT * FROM t ORDER BY (WITH ins AS (INSERT INTO u (a) VALUES (1) RETURNING a) SELECT a FROM ins)
SELECT * FROM t LIMIT (WITH ins AS (INSERT INTO u (a) VALUES (1) RETURNING a) SELECT a FROM ins)
INSERT INTO t (a) WITH del AS (DELETE FROM u RETURNING a) SELECT a FROM del
INSERT INTO t (a) WITH upd AS (UPDATE u SET a = 1 RETURNING a) SELECT a FROM upd
UPDATE t SET a = (WITH ins AS (INSERT INTO u (a) VALUES (1) RETURNING a) SELECT a FROM ins)
DELETE FROM t WHERE a IN (WITH upd AS (UPDATE u SET a = 1 RETURNING a) SELECT a FROM upd)
SELECT 1 UNION SELECT a INTO new_table FROM t
WITH a AS (SELECT 1 AS x) SELECT x INTO new_table FROM a
SELECT * FROM (SELECT a INTO new_table FROM t) x

# --- schema changes ----------------------------------------------------------
CREATE TABLE t (a int)
CREATE TABLE IF NOT EXISTS t (a int PRIMARY KEY, b text NOT NULL)
CREATE TEMP TABLE t (a int)
CREATE UNLOGGED TABLE t (a int)
CREATE TABLE t AS SELECT * FROM u
CREATE TABLE t (LIKE u)
CREATE VIEW v AS SELECT 1
CREATE OR REPLACE VIEW v AS SELECT 1
CREATE MATERIALIZED VIEW v AS SELECT 1
CREATE INDEX i ON t (a)
CREATE UNIQUE INDEX CONCURRENTLY i ON t (a)
CREATE SCHEMA s
CREATE DATABASE d
CREATE SEQUENCE s
CREATE TYPE mood AS ENUM ('a', 'b')
CREATE DOMAIN d AS int
CREATE ROLE r
CREATE USER u
CREATE EXTENSION IF NOT EXISTS pgcrypto
CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1'
CREATE OR REPLACE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql
CREATE PROCEDURE p() LANGUAGE sql AS 'SELECT 1'
CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION f()
CREATE POLICY p ON t USING (true)
CREATE RULE r AS ON INSERT TO t DO NOTHING
CREATE SERVER s FOREIGN DATA WRAPPER w
CREATE PUBLICATION p FOR ALL TABLES
CREATE SUBSCRIPTION s CONNECTION 'x' PUBLICATION p
CREATE OPERATOR === (LEFTARG = int, RIGHTARG = int, FUNCTION = f)
CREATE AGGREGATE a (int) (SFUNC = f, STYPE = int)
CREATE COLLATION c (locale = 'C')
CREATE FOREIGN TABLE ft (a int) SERVER s
CREATE TABLESPACE ts LOCATION '/made/up'
DROP TABLE t
DROP TABLE IF EXISTS t CASCADE
DROP VIEW v
DROP INDEX i
DROP SCHEMA s
DROP DATABASE d
DROP SEQUENCE s
DROP TYPE mood
DROP DOMAIN d
DROP ROLE r
DROP USER u
DROP EXTENSION pgcrypto
DROP FUNCTION f
DROP PROCEDURE p
DROP TRIGGER tr ON t
DROP POLICY p ON t
DROP OWNED BY r
ALTER TABLE t ADD COLUMN b int
ALTER TABLE t DROP COLUMN b
ALTER TABLE t RENAME TO u
ALTER TABLE t ENABLE ROW LEVEL SECURITY
ALTER TABLE t DISABLE ROW LEVEL SECURITY
ALTER TABLE t OWNER TO r
ALTER INDEX i RENAME TO j
ALTER VIEW v AS SELECT 2
ALTER ROLE r WITH SUPERUSER
ALTER USER u WITH PASSWORD 'made-up'
ALTER POLICY p ON t USING (false)
ALTER TYPE mood ADD VALUE 'c'
ALTER SCHEMA s RENAME TO s2
ALTER SEQUENCE s RESTART
ALTER DATABASE d SET x = 1
ALTER SYSTEM SET x = 1
ALTER FUNCTION f() OWNER TO r
ALTER EXTENSION pgcrypto UPDATE
ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO r
TRUNCATE t
TRUNCATE TABLE t, u RESTART IDENTITY CASCADE
GRANT SELECT ON t TO r
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO r
GRANT r TO u
REVOKE SELECT ON t FROM r
REASSIGN OWNED BY r TO u
SECURITY LABEL ON TABLE t IS 'x'
COMMENT ON TABLE t IS 'x'
REINDEX TABLE t
REFRESH MATERIALIZED VIEW v
CLUSTER t
VACUUM
VACUUM FULL t
ANALYZE
ANALYZE t
CHECKPOINT
IMPORT FOREIGN SCHEMA s FROM SERVER x INTO y

# --- statements with no use from a module ------------------------------------
COPY t TO STDOUT
COPY t FROM STDIN
COPY t TO PROGRAM 'made-up-command'
COPY t FROM '/made/up/path'
COPY (SELECT * FROM t) TO '/made/up/path'
SET search_path TO public
SET search_path = public
SET LOCAL search_path TO public
SET SESSION x = 1
SET ROLE r
SET LOCAL ROLE r
SET ROLE NONE
RESET ROLE
RESET ALL
RESET search_path
SET SESSION AUTHORIZATION r
SET TIME ZONE 'UTC'
SET NAMES 'utf8'
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE
SET CONSTRAINTS ALL DEFERRED
SET x.y = 'z'
SHOW search_path
SHOW ALL
SHOW TABLES
SHOW server_version
LISTEN ch
NOTIFY ch
NOTIFY ch, 'payload'
UNLISTEN ch
UNLISTEN *
PREPARE p AS SELECT 1
PREPARE p (int) AS DELETE FROM t WHERE id = $1
EXECUTE p
EXECUTE p (1)
DEALLOCATE p
DEALLOCATE ALL
BEGIN
BEGIN TRANSACTION
BEGIN ISOLATION LEVEL SERIALIZABLE
START TRANSACTION
COMMIT
END
ROLLBACK
ABORT
ROLLBACK TO SAVEPOINT s
SAVEPOINT s
RELEASE SAVEPOINT s
RELEASE s
DISCARD ALL
DISCARD PLANS
USE d
LOAD 'made_up_library'
INSTALL made_up
PRAGMA x
LOCK TABLE t
LOCK TABLE t IN ACCESS EXCLUSIVE MODE
LOCK TABLES t WRITE
UNLOCK TABLES
KILL 1
DECLARE c CURSOR FOR SELECT 1
FETCH NEXT FROM c
FETCH ALL IN c
MOVE NEXT FROM c
CLOSE c
CLOSE ALL
CALL p()
CALL p(1, 2)
DO $$ BEGIN DELETE FROM t; END $$
DO LANGUAGE plpgsql $$ BEGIN PERFORM 1; END $$
EXPLAIN SELECT 1
EXPLAIN ANALYZE SELECT 1
EXPLAIN ANALYZE DELETE FROM t
EXPLAIN (ANALYZE, BUFFERS) INSERT INTO t (a) VALUES (1)
EXPLAIN ANALYZE CREATE TABLE x AS SELECT 1
EXPLAIN t
DESCRIBE t
ATTACH DATABASE 'x' AS y
DETACH DATABASE y
FLUSH TABLES
OPTIMIZE TABLE t
ASSERT 1 = 1
RAISE NOTICE 'x'
PRINT 'x'
RETURN 1
IF 1 = 1 THEN SELECT 1; END IF
WHILE 1 = 1 DO SELECT 1; END WHILE
BEGIN SELECT 1; END
OPEN c
RENAME TABLE t TO u
EXPORT DATA OPTIONS(uri = 'x') AS SELECT 1
DENY SELECT ON t TO r
THROW
WAITFOR DELAY '00:00:01'

# --- denied functions --------------------------------------------------------
SELECT set_config('search_path', 'x', false)
SELECT SET_CONFIG('search_path', 'x', false)
SELECT pg_catalog.set_config('search_path', 'x', false)
SELECT "set_config"('search_path', 'x', false)
SELECT public.set_config('search_path', 'x', false)
SELECT a.b.set_config('search_path', 'x', false)
SELECT pg_notify('ch', 'x')
SELECT query_to_xml('DELETE FROM t', true, true, '')
SELECT pg_catalog.query_to_xml('SELECT 1', true, true, '')
SELECT table_to_xml('t', true, true, '')
SELECT cursor_to_xml('c', 1, true, true, '')
SELECT schema_to_xml('public', true, true, '')
SELECT database_to_xml(true, true, '')
SELECT * FROM xmltable('/a' PASSING x COLUMNS a int PATH 'a')
SELECT * FROM t, XMLTABLE('/a' PASSING t.x COLUMNS a int PATH 'a') AS q
SELECT * FROM t JOIN LATERAL xmltable('/a' PASSING t.x COLUMNS a int PATH 'a') q ON true
WITH q AS (SELECT * FROM xmltable('/a' PASSING x COLUMNS a int PATH 'a')) SELECT * FROM q
INSERT INTO t (a) SELECT a FROM xmltable('/a' PASSING x COLUMNS a int PATH 'a')
SELECT pg_advisory_lock(1)
SELECT pg_advisory_xact_lock(1)
SELECT pg_try_advisory_lock(1)
SELECT pg_advisory_unlock_all()
SELECT lo_import('/made/up')
SELECT lo_export(1, '/made/up')
SELECT lo_unlink(1)
SELECT lo_from_bytea(0, 'x')
SELECT a FROM t WHERE set_config('x', 'y', false) IS NOT NULL
SELECT a FROM t ORDER BY pg_advisory_lock(a)
SELECT a FROM t GROUP BY a HAVING pg_advisory_lock(a) IS NULL
SELECT count(*) FILTER (WHERE pg_advisory_lock(a) IS NULL) FROM t
SELECT sum(a) OVER (ORDER BY pg_advisory_lock(a)) FROM t
SELECT CASE WHEN true THEN set_config('x', 'y', false) END
SELECT coalesce(set_config('x', 'y', false), 'z')
SELECT (set_config('x', 'y', false))
SELECT set_config('x', 'y', false)::text
SELECT * FROM set_config('x', 'y', false)
SELECT * FROM pg_catalog.set_config('x', 'y', false)
SELECT * FROM query_to_xml('SELECT 1', true, true, '') q
SELECT * FROM t, LATERAL query_to_xml('SELECT 1', true, true, '') q
SELECT * FROM ROWS FROM (query_to_xml('SELECT 1', true, true, '')) q
SELECT * FROM t JOIN LATERAL lo_import('/made/up') x ON true
WITH a AS (SELECT set_config('x', 'y', false)) SELECT * FROM a
SELECT * FROM (SELECT pg_notify('ch', 'x')) q
SELECT 1 UNION SELECT length(set_config('x', 'y', false))
INSERT INTO t (a) VALUES (set_config('x', 'y', false))
INSERT INTO t (a) SELECT set_config('x', 'y', false)
INSERT INTO t (a) VALUES (1) RETURNING set_config('x', 'y', false)
INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET b = set_config('x', 'y', false)
UPDATE t SET a = set_config('x', 'y', false)
UPDATE t SET a = 1 WHERE pg_advisory_lock(1) IS NULL
DELETE FROM t WHERE lo_unlink(a) = 1
DELETE FROM t RETURNING pg_notify('ch', a)
MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN UPDATE SET a = set_config('x', 'y', false)
SELECT pg_sleep(1)
SELECT pg_read_file('/made/up')
SELECT pg_read_server_files()
SELECT pg_ls_dir('.')
SELECT pg_terminate_backend(1)
SELECT pg_cancel_backend(1)
SELECT * FROM dblink('made-up', 'SELECT 1') AS x(a int)
SELECT dblink_exec('made-up', 'DELETE FROM t')
SELECT pg_reload_conf()
SELECT pg_stat_reset()
SELECT current_setting('x')
SELECT a FROM t WHERE a = ANY(ARRAY(SELECT set_config('x', 'y', false)))
SELECT ARRAY[set_config('x', 'y', false)]
SELECT ROW(set_config('x', 'y', false))
SELECT set_config(set_config('x', 'y', false), 'z', false)
SELECT a FROM t LIMIT length(set_config('x', 'y', false))
SELECT a FROM t OFFSET length(set_config('x', 'y', false))
SELECT a FROM t FETCH FIRST length(set_config('x', 'y', false)) ROWS ONLY
SELECT DISTINCT ON (set_config('x', 'y', false)) a FROM t
SELECT a FROM t TABLESAMPLE BERNOULLI (length(set_config('x', 'y', false)))
SELECT * FROM t JOIN u ON set_config('x', 'y', false) = u.a
SELECT a FROM t WINDOW w AS (PARTITION BY set_config('x', 'y', false))
SELECT a FROM t FOR UPDATE OF t
VALUES (set_config('x', 'y', false))
SELECT extract(epoch FROM set_config('x', 'y', false)::timestamptz)
SELECT a FROM t WHERE a IN (SELECT pg_advisory_lock(1))
SELECT a FROM t WHERE a BETWEEN lo_import('/made/up') AND 2
SELECT set_config ('x', 'y', false)
SELECT set_config/**/('x', 'y', false)
SELECT pg_catalog . set_config('x', 'y', false)
SELECT (pg_catalog.set_config)('x', 'y', false)

# --- more than one statement, and none ---------------------------------------
SELECT 1; SELECT 2
SELECT 1; DROP TABLE t
SELECT 1; DELETE FROM t
SELECT 1;;
;
; SELECT 1
-- only a comment
/* only a comment */
SELECT 1 -- ; DROP TABLE t
SELECT 1 /* ; DROP TABLE t */
SELECT 'a;b'; DELETE FROM t
SELECT $$a$$; DELETE FROM t
SELECT $x$ $$ ; $x$; DELETE FROM t
SELECT E'\'; DELETE FROM t; --'
SELECT 'a\'; DELETE FROM t; --'
SELECT U&'d\0061t\+000061'
SELECT 1 /* /* */ ; DELETE FROM t; -- */
SELECT "a;b" FROM t
SELECT 1 FROM t WHERE a = 'x' -- '; DELETE FROM t
BEGIN; DELETE FROM t; COMMIT
SELECT (((((((((((((((((((((1)))))))))))))))))))))
SELECT
SELECT FROM
SELEC 1
INSERT INTO
)(
