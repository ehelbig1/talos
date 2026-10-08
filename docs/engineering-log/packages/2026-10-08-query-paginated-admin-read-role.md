# `query_paginated` runs as a least-privilege role (2026-10-08)

The platform-admin MCP tool `query_paginated` runs SQL its caller writes,
across every tenant. After #1201 it runs inside `BEGIN READ ONLY` on a
connection that is closed afterwards; after #1204 the statement is parsed and
must be one read that calls only allow-listed functions and names only public
tables that are not withheld. It still ran as the pool's role: a superuser on
the operator's deployment. This package puts a role between the statement and
the data, as #1201's record proposed: "the parsed gate first, then the role
behind it". #1204 (the gate) merged first.

## Decided

* **A role, `talos_admin_read`** (`migrations/20261008200000_talos_admin_read_role.sql`),
  following the `talos_guest` precedent (`20260522120000`): NOLOGIN NOSUPERUSER
  NOCREATEDB NOCREATEROLE NOINHERIT, a member of nothing, the migrating user a
  member of it so `SET LOCAL ROLE` works.
* **BYPASSRLS, not policies** (measured, below). The tool reads across tenants
  by design; the row-security policies are written for the application's
  tenant context.
* **Explicit table grants.** USAGE on schema `public` and SELECT, by name, on
  each of the 76 tables and views in `public` the tool may read today — every
  one not withheld by `BLOCKED_TABLES_LIST` and not owned by an extension.
  Nothing on a withheld table, nothing on a sequence, no column grants, and no
  default privileges: a table a later migration adds is unreadable through the
  tool until a migration grants it, and Postgres's refusal names it.
* **`AdvancedRepository::execute_paginated_select`**, after `BEGIN READ ONLY`,
  sends one batch — `SET LOCAL ROLE "talos_admin_read"; SELECT rolbypassrls,
  rolsuper FROM pg_roles WHERE rolname = current_user` — and **refuses**
  (`PaginatedSelectError::RoleUnavailable`) when the role cannot be entered
  (missing, the pool's role not a member), lacks BYPASSRLS (a read would
  silently miss rows), or is a superuser (no boundary). It never falls back to
  the pool's role. The handler tells the operator what to run
  (`PaginatedSelectError::role_remedy`), and logs the database's detail.
* **The refusal for an ungranted table names it**:
  `ungranted_relation` reads Postgres's "permission denied for table t"
  (SQLSTATE 42501) and the handler says the table is not granted to the role.
* **One rule line added to `CLAUDE.md`** (Migration Rules): a migration that
  creates a table or view in `public` grants it to the role or withholds it by
  name.

## Measured

On a throwaway Postgres 17.11 from the pinned image, migrated (363
migrations, `scripts/dev-test-db.sh`), as the superuser the operator's pool
connects as.

**The schema.** 89 tables and 3 views in `public` (2 of the views belong to
`pg_stat_statements`), no other non-system schema, no partitioned table, no
sequence (every key is a UUID). 31 tables have row security; their 31 policies
are permissive, apply to every role, and 10 contain a subquery. No restrictive
policy.

**Cross-tenant reads.** Two made-up tenants, one row each in four row-secured
tables, read inside `BEGIN READ ONLY; SET LOCAL ROLE <r>`:

| table | pool role | role without BYPASSRLS | role with BYPASSRLS |
|---|---|---|---|
| `actors` | 2 | 2 | 2 |
| `workflows` | 2 | 2 | 2 |
| `workflow_executions` | 2 | 2 | 2 |
| `scratch_sessions` | 2 | **0** | 2 |

Most policies admit every row when no tenant context is set;
`scratch_sessions`'s admits none, silently. A policy for the role
(`FOR SELECT TO <r> USING (true)`) also returned 2 — but policies are OR'ed and
each is evaluated as the querying role, so with `workflows` ungranted, reading
`workflow_executions` under the policy route failed with "permission denied for
table workflows" (its policy's subquery), where the BYPASSRLS role read it.
Policies would couple each table's grant to every table its policies read, and
a new row-secured table without a policy for the role would read short. Hence
BYPASSRLS, and the refusal when the role lacks it.

**What Postgres refused under the role** (inside the read-only transaction):

| statement | result |
|---|---|
| `SELECT count(*) FROM users` / `secrets` | permission denied for table |
| `SELECT count(*) FROM pg_authid` | permission denied for table |
| `pg_read_file(…)`, `pg_ls_dir(…)`, `pg_stat_reset()`, `pg_reload_conf()` | permission denied for function |
| `pg_terminate_backend(<a superuser's backend>)` | permission denied to terminate process |
| `query_to_xml('SELECT * FROM users', …)` | permission denied for table users (the inner query) |
| `SELECT count(*) FROM pg_catalog.pg_class` | **read** (system catalogs are readable by PUBLIC) |
| `SELECT set_config('role', '<the pool role>', true)` | **succeeded**: the statement's role is the pool's again |

The last two rows are why the role is not a boundary alone. The parsed gate in
front (#1204) refuses both: a `pg_*` relation and any schema but `public` by
name, and `set_config` because it is not on the function allow list. Each
layer covers what the other cannot: the gate cannot see what a name resolves
to; the role cannot stop a statement that resets it.

**A managed Postgres** (a second throwaway container, the migration's
role-creation block run as non-superusers): as a user without CREATEROLE, the
role is not created and a NOTICE says so; as a CREATEROLE user without
BYPASSRLS, the role is created without it and a NOTICE names the `ALTER ROLE`
to run. A CREATEROLE user could grant itself membership and `SET LOCAL ROLE`
into the role. The tool refuses in both states rather than run as the pool's
role. A third state was found by measuring: the role made beforehand by a
superuser, the migration run by a CREATEROLE user. The first draft's
`COMMENT ON ROLE` and membership `GRANT` failed there with insufficient
privilege — and the controller applies migrations at start-up and refuses to
boot on an error. Both now fall back to a NOTICE (the tool then refuses with
the commands to run); measured: the migration completes, 76 grants applied.

**Cost per call.** The role step is one more round trip:
`BEGIN READ ONLY; ROLLBACK` on an open connection, 1000 times: median 0.373 ms
(p95 0.555); with the role batch in between: median 0.769 ms (p95 1.164), so
**+0.40 ms**. Through the real method (release build, 3 × 300 calls of a
200-row select, a fresh connection each since #1201): median 14.14 ms before,
14.96 ms after, round-to-round spread 13.5–15.8 ms. In this environment
(Docker in a VM) opening a connection costs about 14 ms, against #1201's
3.7 ms on the operator's machine; the added 0.4 ms is the comparable figure.

## Tests

* `talos-advanced-repository/tests/admin_read_role_grants.rs` (store
  `migrated`): no privilege of any kind (table or column) on a withheld table;
  SELECT on every other relation in `public` and nothing beyond SELECT; no
  default privileges, no sequence, no role membership; the role's attributes.
* `talos-advanced-repository/tests/paginated_select_role.rs` (store
  `migrated`), through the real method: a granted row-secured table read across
  tenants (`scratch_sessions`, both rows) and `current_user` is the role; an
  ungranted table (`users`, `secrets`, `api_keys`, `pg_authid`) refused by
  Postgres and named by `ungranted_relation`; the refusal when the role is
  missing, lacks BYPASSRLS, is a superuser, or the pool's role (a LOGIN role
  made by the test) is not a member.
* `paginated_select_session.rs` (store `selfcontained`): the fixture creates
  the role when the cluster has none and grants it WRITE privileges on the
  fixture's own schema, so what refuses a write there is still the read-only
  transaction, not the role.
* A flake found while mutation-testing and fixed: two tests granting on one
  object at once can fail one GRANT ("tuple concurrently updated"); the tests
  that grant hold a mutex, and the schema grants were dropped (`public`'s
  default USAGE covers them). Eight consecutive runs of all three files green
  afterwards.

**Mutations** (code: applied, the role tests run, the file restored and its
SHA-256 compared — equal in all five; state: applied to the test database and
undone):

| mutation | caught by |
|---|---|
| no `SET LOCAL ROLE` (the attribute check still runs, as the pool's superuser role) | all 5 role tests |
| no role switch and no check: the statement runs as the pool's role | all 5 role tests |
| a role that cannot be entered falls back to the pool's role (rollback, begin, carry on) | the missing-role and not-a-member tests |
| the BYPASSRLS check removed | the without-BYPASSRLS test |
| the superuser check removed | the superuser test |
| state: `GRANT SELECT ON users` to the role | the grants test |
| state: `ALTER ROLE … NOBYPASSRLS` | the attributes test; the role tests refuse (cross-tenant read, ungranted-table test) |
| state: a new table with no decision | the grants test (names it) |
| state: default privileges for future tables | the defaults test |
| state: INSERT granted on a granted table | the grants test |

## Run

In a cloud session (Linux), not the operator's machine; nothing was measured
on the operator's live database.

* `cargo clippy --workspace --all-targets -- -D warnings`: clean.
* `make lint`: passes, and passes again with check 88's database leg on
  (`TALOS_LINT_SQL_PREPARE=1` against the migrated database: 1257 static
  statements prepare). Legs not run here: 5 and 93 (no `helm`), 7 (clippy, run
  above), 36 (networked audit), 72 (no personal-marker list; the diff was
  searched by hand).
* `make test-unit`: 7517 run, 7517 passed, 2 skipped.
* `admin_read_role_grants` (3), `paginated_select_role` (5) on a fresh clone of
  the migrated template with the final migration, and `paginated_select_session`
  (4) on an empty database: all pass, none skipped, three runs in a row (and
  eight in a row before the last migration change). Containers removed
  afterwards.
* `scripts/ci_test_targets.py check`: the two new binaries are discovered as
  store `migrated`, the session binary stays `selfcontained`.

## Deploy

The migration runs before the new controller uses the role (sqlx migrates at
controller start-up, before it serves). On a database where the migration
could not create the role, or could not give it BYPASSRLS, `query_paginated`
refuses with the commands to run; nothing else changes. Rolling back the
controller restores the previous behaviour (the pool's role); the role and its
grants are harmless left in place.

## Stated limits

* **BYPASSRLS is the point and the cost.** The role reads every row of every
  table it is granted; tenant isolation does not apply to it, by design of the
  tool. What bounds it is which tables it is granted.
* **Not a boundary alone**: a statement that could call `set_config('role', …)`
  or name a catalog would undo or step around it (measured). It depends on
  #1204's parsed gate, and a change that widens that gate must be read with
  this in mind.
* **PUBLIC still applies.** The role inherits PUBLIC's grants like every role:
  EXECUTE on most functions (the allow list is what limits calls), SELECT on
  the system catalogs (the gate refuses `pg_*` names and other schemas).
* **A view reads as its owner.** `user_modules` (granted) reads `modules`
  (granted too). A future view over a withheld table would expose it through
  the view's grant.
* **The session user is still the pool's role.** `session_user` is unchanged,
  and what the role cannot do the session could, if anything let the statement
  reset the role. A second database login for the tool, with no superuser
  session behind it, is the stronger boundary.
* **Granted = readable today.** The 76 grants reproduce what the tool could
  read before this package; no table moved in or out of
  `BLOCKED_TABLES_LIST`.

## Decisions for the operator

* **A second database login for the tool** (a pool that connects as a
  non-superuser), so no superuser session sits behind the role. A deployment
  change.
* **Tables not withheld today that hold authentication-adjacent data**, all
  readable through the tool before and after this package:
  `integration_state` (per-user watch state; a `value` jsonb beside its
  encrypted column), `auth_audit_log` (emails, IP addresses, user agents),
  `integration_credentials` (vault paths, not secrets), the token tables
  `execution_approval_tokens`, `ops_alert_correction_tokens`,
  `workflow_action_tokens` and `worker_provisioning_tokens` (hashes only),
  `plaid_items`, `github_app_installations`. Withholding one is a line in
  `BLOCKED_TABLES_LIST` and a `REVOKE` in a migration.

## Deliberately not done

* A second database login (above), and `TALOS_RPC_GUEST_ROLE` on the
  operator's deployment.
* Removing any of `query_paginated`'s text rules.
* Row-security policies for the role (measured above, rejected).
