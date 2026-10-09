# Module SQL runs as `talos_guest` by default, and never unfenced by mistake (2026-10-09)

Talos runs SQL a caller writes in two places: the platform-admin
`query_paginated` tool, hardened by #1201–#1209, and module SQL (a
`database`-world WASM module's queries, which the controller runs for it on
`talos.database.query`). Module SQL has a role fence, `TALOS_RPC_GUEST_ROLE`
→ `SET LOCAL ROLE talos_guest` (migration `20260522120000`). That fence had
the weaknesses `query_paginated` had before #1205. The operator chose to fix
them next (2026-10-09).

## Found

* **No deployment file set the fence.** Neither compose file nor the chart
  set `TALOS_RPC_GUEST_ROLE`, so module SQL ran as the app user (a superuser
  on compose's bundled Postgres). The production boot gate
  (`enforce_production_db_sandbox_posture`) never fires on compose, because
  `docker-compose.prod.yml` runs `RUST_ENV: staging`.
* **The chart's default install could not boot.** It renders
  `RUST_ENV: "production"` with neither `TALOS_RPC_GUEST_ROLE` nor
  `TALOS_ALLOW_UNSCOPED_DB_SANDBOX` (rendered and checked), and that gate
  refuses to start the controller without one of them.
* **An invalid value switched the fence off.** `guest_role_for_query` read a
  value that is not a role name as "no fence" and ran guest SQL as the app
  user, with a warning. Its doc called this acceptable ("the role wrap is
  itself defense-in-depth"). No decision in `DECISIONS.md` records it; #1206
  and #1209 decided the opposite for `query_paginated`: a fence that is set
  but unusable refuses, never falls back.
* **The role's attributes were never checked.** Measured: with a superuser
  "guest role", `SET LOCAL ROLE` succeeds and the statement reads `users`.
  The boot gate checks only the name's syntax.

Also measured: `talos_guest` is NOLOGIN, NOSUPERUSER, no BYPASSRLS,
NOINHERIT, has the pool's user as its only member, and holds 0 table grants.
Under it `SELECT 1+1` runs and `workflows` is refused.

## Decided

* **`GuestRoleSetting`** (`talos-rpc-subscribers`): `Unset`, `Role(name)` or
  `Invalid`, from one parse (`GuestRoleSetting::parse`, which uses
  `is_valid_pg_role_identifier`). It is read once by
  `guest_role_setting()`, which logs `Invalid` at ERROR.
  * `execute_guest_query` takes it. `Invalid` refuses every query before a
    connection is taken (`ConnectionFailed`, "not a valid role name").
  * `Unset` keeps the legacy posture (the app user), which production still
    refuses to boot in unless acknowledged.
  * `guest_role_for_query()` keeps its signature (`Some` only for a valid
    role) for its read-only consumer, `get_sql_statement_report`, and now
    derives from the same setting.
* **Entering the role reads back what it is, in the same round trip**:
  `SET LOCAL ROLE "<role>"; SELECT rolsuper, rolbypassrls FROM pg_roles
  WHERE rolname = current_user`, replacing the bare `SET LOCAL ROLE`, so it
  adds no round trip.
  * A role that is a superuser or has BYPASSRLS confines nothing, so the
    query is refused.
  * A role that cannot be entered (missing, the pool's user not a member)
    was already refused, and still is.
* **Deployment defaults**:
  * both compose files set `TALOS_RPC_GUEST_ROLE: ${TALOS_RPC_GUEST_ROLE-talos_guest}`.
    With no colon, an explicitly empty value in `.env` still opts out
    (checked with `docker compose config`: unset gives `talos_guest`, empty
    gives `""`, a value gives that value).
  * The chart gains `controller.guestSqlRole: talos_guest`. It renders
    unless `controller.env` sets the variable, renders nothing when empty,
    and refuses to render a value that is not a role name. The default chart
    install now boots.
* **No migration.** `talos_guest` and the pool user's membership already
  exist (`20260522120000`).

## Effect

Module SQL is not in use on the operator's deployment (measured for #1202).
With `talos_guest` it reads nothing until an operator grants a table. That is
the intended starting point, and nothing in use changes.

## Tests

* **Unit:** the setting parse (unset, empty and blank are `Unset`; a name
  with surrounding space is `Role`; spaces, a leading digit, `;`, quotes and
  64 characters are `Invalid`).
* **`talos-rpc-subscribers` `guest_role_db_tests`** (new, migrated store;
  CI kind `lib-migrated`, listed in `scripts/test-integration.sh`), on the
  real `execute_guest_query_within`:
  * under `talos_guest`, `current_user` is `talos_guest` and `workflows` is
    refused;
  * an invalid setting refuses;
  * a superuser role, a BYPASSRLS role and a missing role each refuse;
  * a pool whose user is not a member refuses;
  * unset runs as the pool's user.
* **`guest_session::db_tests`** (existing) pass on the new type.

**Mutations.** All six caught; every file's SHA-256 was equal after restore.

| mutation | caught by |
|---|---|
| an invalid setting runs unfenced (the old behaviour) | the invalid-setting test |
| the attribute check removed | the fences-nothing test |
| BYPASSRLS not checked | the fences-nothing test |
| superuser not checked | the fences-nothing test |
| no `SET LOCAL ROLE` (attributes read as the pool's user) | 3 role tests and the existing advisory-lock test |
| the parse reads an invalid value as unset | the parse unit test and the invalid-setting test |

## Run

In a cloud session (Linux), not on the operator's deployment.

* `cargo clippy --workspace --all-targets -- -D warnings`: clean.
* `make lint`: passes, including check 88's database leg and, with helm on
  PATH, the chart legs. Not run: 7 (clippy, run above), 36, 72.
* `make test-scripts`: 35 passed.
* `make test-unit`: 7540 run, 7540 passed, 2 skipped.
* `guest_role_db_tests` (5) and `guest_session::db_tests` (5) on a fresh clone
  of the migrated template: green three runs in a row. The `query_paginated`
  database files (#1205–#1209) pass on the same clone. No test role left
  behind.
* Rendered chart: the default renders `TALOS_RPC_GUEST_ROLE=talos_guest`;
  empty renders nothing; `my_role` renders it; `bad;role` refuses to render;
  `controller.env` wins. `docker compose config` on both compose files: unset
  gives `talos_guest`, empty gives `""`.

## Stated limits

* **Unset still runs as the app user** outside production, the legacy
  posture. The shipped files set the role; a deployment that removes it
  chooses that.
* **PUBLIC still applies to `talos_guest`**: EXECUTE on most functions,
  SELECT on the system catalogs. The function allow list (#1204) in both
  module-SQL gates is what limits calls, as the migration says.
* **The session behind the role is still the pool's user.** A module
  statement that reset the role would run as it. The allow list refuses
  `set_config`. A dedicated login for module SQL, as `query_paginated` now
  has, is the stronger boundary and is not done here.

## Deliberately not done

* **A dedicated login for module SQL.** It would share most of #1206–#1209's
  machinery, but module SQL is unused on this deployment.
* **Refusing `Unset` outside production.** It would break development
  harnesses that use module SQL without the role; production already
  refuses.
