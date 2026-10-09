# Setting up `query_paginated`'s own login in one command (2026-10-09)

#1206 let `query_paginated` connect as a login of its own
(`TALOS_ADMIN_QUERY_DATABASE_URL`) and left the setup to the operator. That
was five manual steps: create the role, generate a password, build the URL,
store it, restart. The operator asked for it to be automated.

## Decided

* **`controller admin-query-login provision | disable`**, a controller
  subcommand (`controller/src/cli.rs`) over
  `talos_advanced_repository::admin_query_provision`. It runs inside the
  controller's container, which already has `DATABASE_URL` and reaches the
  database in every deployment shape (compose, in-cluster Postgres, managed
  Postgres). No new host tool is needed; neither deploy script uses `psql`
  or `python3`.
  * **The password**: 24 bytes from `talos_random`, as 48 hex characters.
    Hex needs no URL escaping, and SASLprep leaves it unchanged.
  * **Only a verifier reaches the database.** The role gets a SCRAM-SHA-256
    verifier computed in the controller (4096 iterations, Postgres's
    default; random 16-byte salt). The plain-text password is in no
    statement, server log line or `pg_stat_statements` row.
    `provision_statements` takes the password and salt and hashes them
    itself, so it is the only place the SQL is written and a caller cannot
    pass the password through.
  * **Before anything changes**, three checks run: the login name; the URL
    built from `DATABASE_URL` (same host, port, database and parameters,
    credentials replaced; refused if not `postgres://`, no host, or a
    `user` / `password` / `passfile` parameter that would override it); and
    the tool's own reading of that URL (the production TLS rule).
  * **One transaction**, as `DATABASE_URL`'s user: `CREATE ROLE` (or `ALTER
    ROLE` when it exists) `WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '<verifier>'`, then `GRANT
    talos_admin_read`. An existing login is put back to LOGIN only. Anything
    else it holds (another membership, an object, a grant) is not removed:
    the closing check reports it and the operator decides.
  * **The closing check**: the login is used once through
    `execute_paginated_select` with the new URL, the same per-call checks the
    tool runs. If they refuse it, the URL is not handed out.
  * **Output**: the URL goes to stdout only when stdout is not a terminal
    (`--show` overrides that). The refusal comes before anything changes,
    because a rotated password nobody can read is a login nobody can use.
    Errors never carry the password or the URL. `ProvisionedLogin`'s
    `Debug` hides the URL, and secrets are held in `Zeroizing`.
  * `disable` sets `NOLOGIN`. Membership and attributes stay, so `provision`
    restores the login.
* **`scripts/setup-admin-query-login.sh --compose [--env-file P] | --k3s
  [--remove]`**:
  * Runs `provision` in the running controller (`docker compose exec -T` or
    `kubectl exec`) and captures the URL in a variable. It is never echoed,
    and never on any command line: awk reads it from the environment, and
    the k3s helper reads it from stdin.
  * Writes the URL atomically (a temporary file in the same directory, mode
    600, then `mv`):
    * compose: `.env`;
    * k3s: the bootstrap Secret through `scripts/patch-bootstrap-secret.sh`
      (which restarts the controller), and `/etc/talos/install.env` when it
      exists.
  * Restarts the controller. Compose uses `up -d controller`, because
    `restart` does not re-read `.env`.
  * Waits up to 2 minutes for `query_paginated connects as its own login`
    in the controller's log.
  * If provisioning fails, or returns something that is not a database URL,
    nothing is written and nothing restarts.
  * `--remove` takes the line out, restarts, then disables the login.
* **`scripts/patch-bootstrap-secret.sh` accepts a value piped with no
  trailing newline.** `read` reports end-of-input even after reading such a
  final line, so `echo -n "$V" | … KEY=-`, the form its own README examples
  use, failed with "No stdin available" (measured). This also affected the
  manual step in `docs/query-paginated-login.md`, and the instructions given
  to the operator in this session. Now an empty value is the failure, not
  `read`'s status.

## Measured

* **The verifier.** Postgres 17.11 hashed a known password. The Rust
  verifier for the same salt and count matches it byte for byte (a unit
  test pins it), and so does Python's `hashlib`.
* **The subcommand against a migrated database**, over a connection that
  checks passwords. The image's `pg_hba.conf` trusts 127.0.0.1 inside the
  container, where a first check wrongly showed an old password still
  working.
  * `provision` creates the login and its URL logs in. The stored
    `rolpassword` is `SCRAM-SHA-256$4096:…`; attributes `LOGIN` only,
    `NOINHERIT`.
  * A second `provision` rotates the password: the old URL is refused
    ("password authentication failed") and the new one logs in.
  * A wrong password is refused.
  * `disable` leaves the login unable to connect.
  * With stdout a terminal, `provision` refuses and changes nothing.
* **The script with the real binary behind a `docker` shim**:
  * `.env` holds the URL at mode 600;
  * the password appears nowhere in the script's output (counted);
  * the stored URL logs in as `talos_admin_query`;
  * `--remove` takes the line out and the old URL no longer logs in.

## Tests

* **Unit tests (`admin_query_provision::tests`)**:
  * the Postgres verifier vector;
  * a 48-hex password that never repeats;
  * the login URL keeps host, port, database and `sslmode` and drops the
    pool's password;
  * a `DATABASE_URL` that cannot carry the login is refused without being
    quoted;
  * the statements carry the verifier and never the password;
  * `Debug` hides the URL.
* **`talos-advanced-repository/tests/admin_query_provision.rs`** (store
  `migrated`, 5 tests):
  * a new login has LOGIN only and a SCRAM verifier, is a member of the
    role, and its URL connects;
  * provisioning again rotates the password;
  * an existing login with CREATEDB and INHERIT is normalised;
  * one in `pg_read_all_data` is refused and not stripped;
  * production refuses a non-TLS URL before anything is made;
  * disable, then provision again, restores the login.
* **`scripts/tests/setup-admin-query-login-test.sh`** (fakes on PATH):
  * compose first setup, rotation (one line, no leftover temp file), a
    failed provision and a non-URL reply (each leaving `.env` unchanged and
    nothing restarted), `--remove` (restart before disable), and a new
    `--env-file`;
  * k3s setup: the Secret patch carries the URL, `install.env` too, the URL
    is on no command line and in no output;
  * k3s `--remove`;
  * the helper accepts a value with no trailing newline and still refuses an
    empty one. Against the helper as it was, those two checks fail.

**Mutations.** All 11 caught; every file's SHA-256 was equal after restore.

| mutation | caught by |
|---|---|
| the password itself sent as `PASSWORD` | the statements unit test (only it: Postgres hashes a plain password itself, so the stored result looks the same) |
| Client Key and Server Key swapped | the vector test and 4 database tests |
| PBKDF2 block index 0 | the vector test and 4 database tests |
| the URL keeps the pool's password | the URL unit test and 4 database tests |
| a constant password | the password unit test and the rotation test |
| `NOINHERIT` dropped | the new-login and normalise tests |
| `NOCREATEDB` dropped | the normalise test |
| no `GRANT` of the role | the statements unit test and 4 database tests |
| the closing check skipped | the not-stripped test |
| the production TLS refusal skipped | the production test |
| `disable` does not take LOGIN away | the disable test |

The terminal guard is not mutated: it is in the controller binary's CLI glue
and was checked by hand (above).

## Run

In a cloud session (Linux), not on the operator's deployment.

* `cargo clippy --workspace --all-targets -- -D warnings`: clean.
* `make lint`: passes, including check 88's database leg and the helm chart
  legs. Not run: 7 (clippy, run above), 36 (networked audit), 72.
* `make test-scripts`: 35 passed, the new one included.
* `make test-unit`: 7532 run, 7532 passed, 2 skipped.
* The five `talos-advanced-repository` database files: green three runs in a
  row on a fresh clone of the migrated template, no test role left behind.

## Stated limits

* **The controller's database user must be able to create roles**
  (superuser, or CREATEROLE with the right to grant `talos_admin_read`).
  Where it cannot, provisioning fails with that reason and the manual steps
  remain.
* **The login lives on the cluster, the URL in a deployment's config.** A
  restore of the database onto a new cluster needs `provision` run again.
* **Rotation is not scheduled.** Running the script again rotates; nothing
  runs it periodically.
* **A k3s deployment with several controller replicas**: `kubectl exec`
  provisions from one pod, and the helper's rollout restarts all of them.

## Deliberately not done

* **Provisioning at controller start-up**, with a password derived from a
  key the controller already holds. That would make every boot a role change
  run by the app's own privileged connection, and replicas would race to
  re-set the same role. A one-shot operator command keeps the controller
  from managing database roles at runtime.
* A scheduled rotation.
