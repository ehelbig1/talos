# A `*` secret grant grants nothing, and no authority writes one (2026-10-15)

Operator decision D2-D (security review 2026-10-15 round 2, carrying C-8 from
2026-10-14), taken on the round's recommendation: refuse `*` secret grants for
every authority. Package R10.

## The exposure

`allowed_secrets: ["*"]` was expanded by `SecretsManager::get_secrets_by_paths`
to every secret the module's user could read — every OAuth access token
included — and sealed into each dispatch's envelope; the worker's matcher let
the guest read any of them. A2-1 (R4) refused it for a bearer credential only;
a second-factor session could still write it, and a catalog manifest could
declare it.

## Decided

- **Every writer refuses it, every authority.** `refuse_wildcard_grant`
  answers a bare `*` (trimmed) in `allowed_secrets` with
  `SECRET_WILDCARD_RETIRED` before it looks at the authority;
  `talos_registry::validate_allowed_secrets` (manifest parse, registry upload,
  catalog reconcile, marketplace) refuses it too, and the marketplace install
  answers with the same sentence. `WildcardGrantRefused` now carries the
  sentence it was refused with, so a session is not told to use a second
  factor it already has. `<prefix>/*` is unchanged: a second-factor session's
  to write. A `*` HOST grant is unchanged.
- **The table refuses it whoever writes.** Migration `20261015160000` removes
  `*` from `modules.allowed_secrets` and `owner_added_secrets` with
  `array_remove` (every other entry kept), then adds
  `modules_no_star_secret_grant` on both columns. Those are the only two
  secret-grant columns in the schema (measured on `information_schema`).
  Measured on the reference stack before it: 0 rows held `*` (23 hold a
  `<prefix>/*`, untouched). No new table, so no `talos_admin_read` decision.
- **It grants nothing where it could still appear.** `vault_path_permitted`
  and `vault_path_prefetched` lost their `*` arm (controller and worker share
  them), and `get_secrets_by_paths` lost the branch that expanded `*` — a
  caller-declared rehearsal list that names `*` reads nothing by it. Tests
  that pinned the old meaning are rewritten to pin the new one (the orphan
  report, the beyond/narrow helpers, the blocked-reference report, the worker
  allowlist).
- **The one catalog template that declared it** (`constitutional-refinement`,
  which reads one key whose path the user configures) now grants nothing; its
  config text says to grant the exact path after install.

## Deliberately NOT changed

Report sites that special-case a stored `*` (`analytics` risk A,
`get_module_info`'s `setup_required`, `validate_workflow`'s and the creation
helper's vault-reference short-circuit, `SecretsManager`'s reference reports,
`get_unused_secrets`' wildcard note) read a value the constraint now forbids;
they are unreachable and left as they are.

## Tests

- `talos-capability-world::a_star_secret_grant_is_refused_for_every_authority`.
- `talos-registry`: `validate_allowed_secrets(["*"])` refused.
- `talos-workflow-job-protocol`: `a_star_grant_allows_nothing`,
  `a_star_grant_neither_permits_nor_prefetches`; worker
  `host::vault::…::a_star_grant_allows_nothing`.
- DB `star_secret_grant_tests` (new binary): `no_authority_writes_a_star_secret_grant`
  (the repository writer, both authorities; a glob still written by a
  session), `a_star_grant_delivers_nothing` (two stored secrets, `*` fetches
  none, an exact path one), `the_table_refuses_a_star_on_either_grant_column`,
  `the_migration_strips_a_star_and_keeps_the_rest` (the shipped SQL, re-run
  over a row seeded as before it).
- `module_grant_bearer_tests` expectations: a `*` secret grant answers
  `SECRET_WILDCARD_RETIRED`; a `*` host grant still the second-factor sentence.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| every authority refused | the bare-`*` check removed from `refuse_wildcard_grant` | `no_authority_writes_a_star_secret_grant` | FAIL / PASS restored |
| delivery expands nothing | `manager.rs` as on main (the expansion back) | `a_star_grant_delivers_nothing` | FAIL / PASS restored |
| the matcher grants nothing | `s == "*"` arm restored in `vault_path_permitted` | three protocol tests, the worker allowlist test | FAIL ×4 / PASS restored |

The constraint is not mutation-proven separately: its test reads the constraint
by name from the migrated database.
