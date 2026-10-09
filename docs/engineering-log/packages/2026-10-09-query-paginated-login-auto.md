# `query_paginated`'s own login as part of every deployment (2026-10-09)

After #1208, putting `query_paginated` on its own login was one command, but
still a separate act after each deploy. The operator asked for it to be part
of the deployment process, for both docker compose and Helm. This package
does that: `TALOS_ADMIN_QUERY_LOGIN=auto`, set by the shipped compose files
and the chart.

## This reverses a decision, on new facts

#1208's record listed "provisioning at controller start-up" under
deliberately not done, for two reasons:

* **"Every boot a role change run by the app's own privileged connection."**
  The controller already applies migrations (DDL) at start-up on that
  connection. And the start-up step here changes nothing when the login
  already matches: it connects as the login once and stops.
* **"Replicas would race to re-set the same role."** Measured: without a
  lock, eight concurrent start-ups failed with `tuple concurrently updated`
  or a duplicate `pg_authid_rolname_index` key. A transaction-scoped advisory
  lock (`pg_advisory_xact_lock(hashtext('talos.admin_query_login'),
  hashtext(<login>))`) makes them take turns. With it, all eight succeed and
  exactly one creates the login.

The new fact is the operator's request. The password question it raises —
how every replica gets the same password with nothing new to store — is
answered by deriving it.

## Decided

* **`SecretsManager::admin_query_login_password`**: 32 bytes from
  `KekProvider::derive_purpose_key` (HKDF-SHA-256 over the master key, salt
  `talos-admin-query-login/v1`, info `postgres-login-password`), written as
  64 hex characters. This is `ml_content_mac_key`'s pattern exactly,
  including its fallback for a KMS-backed KEK, which exports nothing:
  HKDF over the global active DEK. Nothing is stored, every replica derives
  the same password, and it is domain-separated from every other derived
  key (tested). Rotating the KEK (or, on the fallback, the DEK) changes it,
  and the next start-up repairs the login.
* **`admin_query_provision::ensure_login`**: if the login already connects
  with the password and passes the tool's per-call checks, it returns
  `AlreadyInPlace` and changes nothing (the stored verifier is unchanged,
  tested). Otherwise it runs #1208's provisioning, now under the advisory
  lock, with the password supplied. The `controller admin-query-login
  provision` path takes the same lock.
* **`admin_query_provision::resolve_startup_login`** holds the start-up rules
  in the crate, so they are tested against a database. The controller's
  `bootstrap/admin_query_login.rs` only gathers the environment and the
  password future, and runs after migrations, before the router.
  * An explicit `TALOS_ADMIN_QUERY_DATABASE_URL` wins: that login, as before.
  * Else, with `auto`, the tool uses the derived login whatever the outcome
    of `ensure_login`. A login made at an earlier start-up keeps working
    through a transient failure, and one that does not work is refused per
    call, never run on the pool. The start-up log says what happened
    (`created`, `repaired`, `already in place`, or the error).
  * `ensure_login` gets 30 s at most; past that the controller starts and
    the tool's calls say why.
  * A password that cannot be derived, or a mode that is neither `auto` nor
    `off`, refuses every call.
  * `off` or unset: the pool, as before. The code default stays `off`, so
    only the shipped deployment files opt in.
* **Deployment files**:
  * `docker-compose.yml` and `docker-compose.prod.yml` set
    `TALOS_ADMIN_QUERY_LOGIN: ${TALOS_ADMIN_QUERY_LOGIN:-auto}`.
  * The chart gains `controller.adminQueryLogin: auto` (values) and renders
    `TALOS_ADMIN_QUERY_LOGIN`, unless `controller.env` sets it. It refuses
    to render any value other than `auto` or `off`, in any case.
  * k3s installs use the chart.
  * A configuration-reference row.
* **The tool's remedy text** says that with `auto` the controller makes and
  repairs the login at start-up, and its log says why it could not.

## Measured

* **Eight concurrent `ensure_login`s on a fresh login**: with the lock, all
  succeed and one creates the login. Without it (the mutation run, plus
  three manual reruns), a replica fails every time, with "tuple concurrently
  updated" or the duplicate key.
* **A second start-up** (`ensure_login` again) returns `AlreadyInPlace`, and
  `pg_authid.rolpassword` is byte-identical.
* **Its cost** is one connection as the login plus the per-call checks:
  about 7.6 ms (the own-login call cost measured for #1206), once per
  controller start.
* **Rendered chart**:
  * default: `TALOS_ADMIN_QUERY_LOGIN=auto`;
  * `adminQueryLogin=off`: `off`;
  * `AUTO`: `auto`;
  * `on`: render refused, naming the value;
  * `controller.env.TALOS_ADMIN_QUERY_LOGIN=off`: that wins.

## Tests

* `talos-secrets-manager`: the password is stable, 64 lower-case hex, and
  not the ML content key.
* `talos-advanced-repository` unit tests: the mode parser (`auto` and `off`
  in any case and spacing; `on`, `true` and typos are `Invalid`).
* `tests/admin_query_provision.rs`, six new tests:
  * the first start-up creates the login and the second changes nothing;
  * a drifted password plus CREATEDB is repaired;
  * eight replicas starting together;
  * `auto` end to end (`session_user` is the login);
  * a failed `auto` set-up (a login in `pg_read_all_data`) refuses with
    `OtherMemberships`, and a password that cannot be derived refuses with
    `Misconfigured`, neither running on the pool;
  * `off` runs as the pool's user, and an invalid mode refuses.

**Mutations.** All six caught; every file's SHA-256 was equal after restore.

| mutation | caught by |
|---|---|
| no advisory lock | the replicas test |
| no fast path (every start-up re-provisions) | the "changes nothing" test |
| a failed `ensure_login` runs the tool on the pool | the failed-`auto` test |
| a password that cannot be derived runs on the pool | the failed-`auto` test |
| an invalid mode runs on the pool | the `off`/invalid test |
| the derived password is the ML content key | the password unit test |

## Run

In a cloud session (Linux), not on the operator's deployment, and without a
compose stack or cluster: the controller's start-up wiring was compiled and
linted, not booted.

* `cargo clippy --workspace --all-targets -- -D warnings`: clean.
* `make lint`: passes, including check 88's database leg and, with helm on
  PATH, the chart legs. The first run failed check 65 once, claiming
  `talos_advisory_db_age_enforced` is registered nowhere. It is registered
  (`talos-metrics/src/lib.rs`), nothing here touches it, and two reruns (with
  and without the database leg) passed, so it was not reproduced or explained.
  Not run: 7 (clippy, run above), 36 (networked audit), 72.
* `make test-scripts`: 35 passed.
* `make test-unit`: 7534 run, 7534 passed, 2 skipped.
* The five `talos-advanced-repository` database files
  (`admin_query_provision` now 11 tests): green three runs in a row on a fresh
  clone of the migrated template, no test role left behind.

## Stated limits

* **The controller's database user must be able to create roles.** On the
  shipped compose Postgres it is a superuser. On a managed Postgres without
  CREATEROLE, the tool refuses calls with the reason in the start-up log;
  `off`, or the manual steps with an explicit URL, remain.
* **KEK rotation.** During the rolling restart after `rotate_master_key`,
  controllers still on the old key hold the old password, so their
  `query_paginated` calls are refused until they restart. Nothing else is
  affected.
* **A transient failure on a first start-up** (the login never made) leaves
  the tool refusing until the next start-up. There is no retry while the
  controller runs.
* **The derived password is as strong as the KEK.** Whoever holds
  `TALOS_MASTER_KEY` can compute it, and that party can already unwrap every
  DEK.

## Deliberately not done

* **Making `auto` the code default.** The deployment files opt in;
  development harnesses and tests keep the pool unless they ask.
* **A retry loop while the controller runs.**
* **Removing #1208's script.** It remains the way to give the login a
  random, rotatable password held outside the KEK's reach, via an explicit
  URL.
