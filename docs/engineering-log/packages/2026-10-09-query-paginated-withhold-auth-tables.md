# `query_paginated` withholds six authentication-adjacent tables (2026-10-09)

The #1205 record listed tables the platform-admin `query_paginated` tool could
still read that hold authentication-adjacent data, and left withholding them to
the operator. The operator chose the recommended set (2026-10-09):

| table | what it holds | decision |
|---|---|---|
| `auth_audit_log` | every user's sign-in history: emails, IP addresses, user agents | withheld |
| `integration_credentials` | where every user's OAuth tokens sit in the vault, by provider and account (paths, not secrets) | withheld |
| `execution_approval_tokens`, `ops_alert_correction_tokens`, `workflow_action_tokens`, `worker_provisioning_tokens` | hashes of bearer tokens | withheld: no diagnostic value |
| `integration_state` | per-user integration watch state | kept |
| `plaid_items` | institution names and item ids; the access token is in the vault | kept |
| `github_app_installations` | installation ids | kept |

The three kept tables are useful when debugging an integration. Neither of
the two that might have held a secret does. The Google Calendar channel token
is recomputed from a shared key rather than stored
(`talos_google_calendar::webhook_token::verify_channel_token`), and
`plaid_items` has no token column.

## Changed

* `BLOCKED_TABLES_LIST` (`talos-admin-query-gate`) gains the six names, so
  both the text rule and the parsed gate refuse a statement that names one.
* Migration `20261009120000_talos_admin_read_withhold_auth_tables.sql` runs
  `REVOKE ALL` on the six from `talos_admin_read`, so Postgres refuses a
  statement the gate did not see. It does nothing when the role does not
  exist. The role now holds 70 table grants (76 before).
* #1205's role remedy, which tells an operator who builds the role by hand
  to run that migration's GRANT statements, now also names this migration's
  REVOKE. Without it, following the remedy would re-grant the withheld
  tables.
* `paginated_select_role.rs`: the Postgres-refusal test now asks every
  withheld table that exists in the schema (20 today; some names stay on the
  list after their table was dropped), not three. A later addition to the
  list is covered with no edit. A floor of 15 keeps the loop from passing
  vacuously.

## Measured

On the migrated schema (365 migrations):

* No view reads any of the six, no column elsewhere is named like one (the
  text rule refuses the word anywhere in a query), and no granted table has
  a foreign key into one.
* The role held exactly SELECT on each before the migration, and nothing
  after.

On a throwaway Postgres from the pinned image, the migration as a managed
deployment would run it:

| case | result |
|---|---|
| the role does not exist | exit 0, nothing to do |
| role and grants made by a superuser by hand, migration run by the CREATEROLE app user that owns the tables | exit 0, the six revoked (Postgres records a superuser's grant on an owned table as made by the owner) |
| the same, run by a superuser | exit 0, the six revoked |
| run twice | exit 0 |

No case fails the migration, which matters because the controller applies
migrations at start-up and refuses to boot on a failure.

## Tests and mutations

* State mutations: SELECT granted back on `auth_audit_log`,
  `integration_credentials` and `worker_provisioning_tokens` in turn. Each is
  caught by the grants test (`every_public_relation_is_granted_to_the_role_or_withheld`).
  Re-granting `auth_audit_log` is also caught on its own by
  `a_table_the_role_is_not_granted_is_refused_by_postgres`, through the real
  method. Each grant was revoked again afterwards.
* Code mutations: each of the six names taken off `BLOCKED_TABLES_LIST`, run
  with `--no-fail-fast`. Each is caught by two independent tests: the gate's
  unit test (`the_auth_adjacent_tables_withheld_2026_10_09_are_refused`) and
  the grants test, which reports the table as revoked but not withheld. Every
  file's SHA-256 was equal after restore.
* The shared SQL corpus names none of the six. All four recorded gate
  snapshots pass unchanged.

## Run

In a cloud session (Linux), not on the operator's database.

* `cargo clippy --workspace --all-targets -- -D warnings`: clean.
* `make lint`: passes, including check 88's database leg and, with helm on
  PATH, the chart legs 5 and 93. Not run: 7 (clippy, run above), 36
  (networked audit), 72 (no personal-marker list; the diff was searched by
  hand).
* `make test-unit`: 7526 run, 7526 passed, 2 skipped.
* `admin_read_role_grants` (3), `paginated_select_role` (5),
  `paginated_select_login` (4) on a fresh clone of the migrated template, and
  `paginated_select_session` (4) on an empty database: all pass, three runs in
  a row, no test login left behind.

## Effect on operators

* The refresh-token-reuse alert's runbook
  (`deploy/helm/talos/files/alerts.yaml`, `TalosRefreshTokenReuse`) gives an
  `auth_audit_log` query as its second source, after the controller log. It
  does not say to use `query_paginated`, which now refuses it. A superuser in
  `psql` still can. The text was left as it is.
* Nothing else in the repository reads these tables through the tool.

## Deliberately not done

* Withholding `integration_state`, `plaid_items` or
  `github_app_installations`: reasons above.
* Editing the #1205 migration: applied migrations are never modified.
