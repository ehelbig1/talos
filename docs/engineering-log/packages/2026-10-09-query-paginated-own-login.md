# `query_paginated` on a database login of its own (2026-10-09)

The platform-admin MCP tool `query_paginated` runs SQL its caller writes. After
#1201 it runs in a read-only transaction on a connection that is closed
afterwards; after #1204 the statement must pass a parsed gate; after #1205 it
runs as `talos_admin_read`, granted SELECT on 76 named public tables. The
#1205 record left one limit and one decision: **the session user is still the
pool's role** (a superuser on the operator's deployment), and "a second
database login for the tool" is the stronger boundary. The operator chose to
build it (2026-10-09). Switching the deployment to it remains the operator's
edit.

## Decided

* **`TALOS_ADMIN_QUERY_DATABASE_URL`** (and `_FILE`, via
  `talos_config::read_env_or_file`), read once at controller start-up by
  `AdminQueryLogin::from_env` (`talos-advanced-repository`) and handed to
  `AdvancedRepository::with_admin_query_login`.
  * **Unset or empty**: the pool, exactly as before.
  * **Set**: each call connects as that login.
  * **Set but unusable**: kept as unusable, and every call is refused. Three
    cases: not a `postgres://` / `postgresql://` URL, an unparseable one, or
    no TLS-guaranteeing `sslmode` in production (the `DATABASE_URL` rule,
    `talos_db::db_url_tls_guaranteed`).
  * A misconfiguration never falls back to the pool, and never stops the
    controller booting. It is an admin tool, and it refuses.
* **Per call, on the tool's own login**: connect (10 s timeout, the pool's
  `acquire_timeout`) with `application_name = talos_admin_query`, then
  `BEGIN READ ONLY; SET LOCAL statement_timeout = '<DB_STATEMENT_TIMEOUT_SECS>s';
  SET LOCAL idle_in_transaction_session_timeout = '60s'` in one round trip. The
  pool sets the same two values per session. Then come #1205's role batch,
  the statement, and the close. `DB_STATEMENT_TIMEOUT_SECS` now has one
  reader, `talos_db::statement_timeout_secs`, shared by the pool, the replica
  pool and this. A zero is never sent, since `'0s'` disables the timeout.
* **The login is checked on every call**, in the same round trip as the
  role's attributes. The call is refused
  (`PaginatedSelectError::LoginUnavailable`, with a `LoginRefusal` the caller
  may see and a detail kept for the log) when the login:
  * cannot connect (`Unreachable`, including a wrong password);
  * is the user the pool connects as (`IsThePoolLogin`, compared before
    connecting);
  * is a superuser;
  * has CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS;
  * belongs to any role but `talos_admin_read`;
  * owns any object, or holds any privilege granted to it directly. One
    indexed `pg_shdepend` lookup covers both, in every database of the
    cluster.

  A login that is not a member of the role fails `SET LOCAL ROLE` and gets
  #1205's role refusal. Its remedy text now names "the user in
  `TALOS_ADMIN_QUERY_DATABASE_URL`, or the controller's database role when
  that is unset".
* **The URL never reaches a log.** sqlx's `PgConnectOptions` derives `Debug`
  with the password in it, so `AdminQueryLogin`'s `Debug` is written by hand
  (user, database, timeout). A parse error is not kept, because it may quote
  the URL. Start-up logs say only which login is in use.
* **Transport**, as `DATABASE_URL`'s is: both compose files' controller
  service (`${TALOS_ADMIN_QUERY_DATABASE_URL:-}`), the chart's bootstrap
  Secret key list and `values.yaml` (blank), and the k3s installer and its
  README. The configuration-reference row is 🔒. The operator page is
  `docs/query-paginated-login.md`.

## Measured

On a throwaway Postgres 17.11 from the pinned image, migrated (364
migrations), with a login `CREATE ROLE … LOGIN NOSUPERUSER NOINHERIT; GRANT
talos_admin_read TO …`, connecting over TCP with SCRAM:

| as the tool's login | result |
|---|---|
| `SELECT count(*) FROM users`, no role entered | permission denied for table users |
| in the role, `set_config('role','none',true)`, then `session_user, current_user` | `login, login` |
| … then `SELECT count(*) FROM users` | **permission denied** |
| the same escape as the superuser pool login | **read** |
| `BEGIN READ ONLY; SET LOCAL statement_timeout = '1s'; …`, then `pg_sleep(2)` | canceled by statement timeout |
| `SET LOCAL idle_in_transaction_session_timeout = '1s'`, then idle 2 s | the server ended the session |
| `pg_shdepend` rows for a fresh login / owning a table / a direct grant / revoked | 0 / 1 / 1 / 0 |
| the login check, under the role | readable; `pg_shdepend` by an index-only scan |

The escape row is the point. The parsed gate refuses `set_config`, so this
statement cannot be sent through the tool. If the gate ever let through
something that resets the role, the reset would land on a login that holds
nothing.

sqlx parses a `mysql://` URL into Postgres options without complaint, so the
scheme is checked explicitly.

**Cost per call** (release build, through `execute_paginated_select`, 3 × 300
calls of a 200-row select per mode, the pool kept 2–4 connections warm, no
TLS in this environment):

| round | pool | own login |
|---|---|---|
| 0 | 3.56 ms median, 8.56 p95 | 7.57 ms median, 9.00 p95 |
| 1 | 3.78 ms, 9.37 | 7.57 ms, 9.63 |
| 2 | 4.10 ms, 9.50 | 7.70 ms, 9.29 |

The own login adds about 3.7 ms median, the connection and SCRAM exchange
now on the request path. The p95s are about equal, because the pool also
opens a connection on the request path when it has none idle. A deployment
with TLS to its database pays a TLS handshake on top. The tool is a manual
admin tool, so this was accepted rather than designed around: a pooled login
would keep sessions alive, which #1201 rejected.

## Tests

* `talos-advanced-repository/tests/paginated_select_login.rs` (store
  `migrated`), through the real method, each test making its own logins:
  * a cross-tenant read of a row-secured table on the tool's login.
    `session_user` is the login, `current_user` the role, the
    `application_name`, `statement_timeout` (as configured),
    `idle_in_transaction_session_timeout` and `transaction_read_only` are as
    set, and no session of the login is left afterwards;
  * a statement longer than the configured timeout is canceled (57014);
  * a refusal for each way the login can be unusable: a wrong password, the
    pool's user, SUPERUSER, CREATEROLE, BYPASSRLS, membership in
    `pg_read_all_data`, a direct grant, an owned schema, and a `mysql://`
    setting;
  * a login outside the role gets the role refusal.
* Unit tests (`admin_query_login_tests`) cover:
  * unset or empty means the pool;
  * a URL's user, database, timeout and `application_name`;
  * a zero timeout is never sent;
  * the production TLS rule;
  * a wrong scheme, a missing scheme and a bad port are each misconfigured,
    with nothing of the URL kept;
  * `Debug` never shows the password;
  * the refusal order;
  * the remedy carries the refusal, not the detail.
* The existing `paginated_select_role` (5), `paginated_select_session` (4) and
  `admin_read_role_grants` (3) pass on the refactored pool path.

**Mutations.** Code mutations were applied, the tests run, the file restored
and its SHA-256 compared; equal in all 19.

| mutation | caught by |
|---|---|
| a dedicated login runs on the pool | all 4 login tests |
| a misconfigured setting runs on the pool | the refusal test |
| a failed connect falls back to the pool | the refusal test |
| the pool's-own-login check removed | the refusal test |
| the login not checked at all | the refusal test |
| a superuser login admitted | the refusal test |
| extra attributes admitted | the refusal test |
| BYPASSRLS dropped from the attribute check | the refusal test |
| other memberships admitted | the refusal test |
| the membership test inverted | the happy path, timeout and refusal tests |
| objects and grants admitted | the refusal test |
| `pg_shdepend` asked about the role, not the login | the happy path and timeout tests |
| no `SET LOCAL statement_timeout` | the timeout and happy-path tests |
| the own connection not read-only | the happy path |
| no `application_name` | the happy path |
| the production TLS rule removed | its unit test |
| the scheme check removed | its unit test |
| `Debug` shows the connect options | its unit test |
| a zero timeout sent as is | its unit test |

Not mutated: the explicit `close()`. Dropping a `PgConnection` closes its
socket too, so the "no session left" test cannot tell the two apart; the
close is a courtesy, not the control.

## Run

In a cloud session (Linux), not the operator's machine; nothing was measured
on the operator's database.

* `cargo clippy --workspace --all-targets -- -D warnings`: clean.
* `make lint`: passes, with check 88's database leg on (1256 static statements
  prepare against the migrated schema) and, with helm 3.16.2 on PATH
  (checksum verified), checks 5 and 93: the chart renders with the new key,
  passed to the controller from the bootstrap Secret. Not run: 7 (clippy, run
  above), 36 (networked audit), 72 (no personal-marker list; the diff was
  searched by hand).
* `make test-unit`: 7525 run, 7525 passed, 2 skipped.
* `paginated_select_login` (4), `paginated_select_role` (5) and
  `admin_read_role_grants` (3) on a fresh clone of the migrated template, and
  `paginated_select_session` (4) on an empty database: all pass, none skipped,
  three runs in a row. A passing run leaves no test login behind (counted).
  Roles are cluster-wide, so a run that panics leaves its logins; the
  mutation runs left 21, which were dropped.
* `controller --test admin_event_visibility_tests` (the controller binary that
  names the tool): 6 passed.
* `scripts/ci_test_targets.py check`: the new binary is discovered as store
  `migrated`.

## Deploy

Nothing changes until `TALOS_ADMIN_QUERY_DATABASE_URL` is set. To switch,
follow `docs/query-paginated-login.md`: create the login, set the URL,
restart. To switch back, unset it. No migration is needed: the login is the
operator's to create, because a migration cannot hold its password.

## Stated limits

* **The login is checked, not created.** Its password, rotation and
  `pg_hba.conf` entry are the operator's.
* **Same database, assumed.** The URL may name another host or database;
  the tool reads whatever it names, and only its user is compared with the
  pool's. A read replica is a legitimate target, a wrong database is a
  misconfiguration the tool cannot see.
* **PUBLIC still applies to the login.** As for every role, the login keeps
  PUBLIC's EXECUTE on most functions and SELECT on the system catalogs, so
  after the escape above it could read the catalogs. The gate refuses the
  escape and catalog names.
* **A login made a superuser later** is refused on its next call, but a
  statement already running finishes as it was.
* **CREATEROLE users elsewhere.** On Postgres 16 and later a CREATEROLE user
  that made the login holds ADMIN on it and could change it. That is the
  operator's role design. The per-call check sees the result, not the
  actor.

## Deliberately not done

* **Requiring the login in production.** It would stop the tool on every
  deployment that has not set it up, which is the operator's decision. The
  code path is opt-in.
* **A pool for the login.** #1201's reason to close every connection (session
  state survives a rollback) holds here too.
* **Creating the login in a migration.** A migration cannot hold a password,
  and a login without one is useless.
* **Withholding more tables** from the role (`integration_state`,
  `auth_audit_log`, the `*_tokens` tables, …). This is #1205's other open
  decision, still the operator's.
