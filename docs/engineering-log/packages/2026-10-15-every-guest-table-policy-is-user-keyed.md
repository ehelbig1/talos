# Every row-security policy is keyed on the user (2026-10-15)

Security review 2026-10-15 (round 2), findings **D2-1** (Medium), **D2-5**
(Low) and **D2-6** (Info). Package R3 of the round-2 remediation; follows R1
(#1316), whose test module it extends.

## The defects, as verified

- **D2-1.** `modules_tenant_isolation` and `webhook_triggers_tenant_isolation`
  were still 20260719120000's org-keyed policies:
  `NULLIF(app.current_org_ids,'') IS NULL OR org_id IS NULL OR org_id = ANY(…)`.
  The guest-SQL transaction sets the signed actor's owner and an EMPTY org
  list (`TenantReadScope::new(owner, Vec::new())`), which that first arm
  reads as "unset" — so `GRANT SELECT ON modules TO talos_guest` (the
  documented way to let `database`-world modules read a table) showed every
  tenant's `source_code`, `config` and `allowed_secrets`, and the same grant on
  `webhook_triggers` every tenant's token hashes and routing. Measured on a
  migrated clone: of the 37 tables in `public` with a policy, these two — and
  only these two — had a read condition without `app.current_user_id`. The
  2026-07-19 loop named fourteen tables; 20260912140000 rekeyed eleven,
  20261015100000 rekeyed `actor_memory`; these two were never named.
- **D2-5.** Check 104 accepted `.bind(<anything>.user_id)` for an unbound
  `user_id` parameter, accepted passing `user_id` to ANY call, and scanned only
  `talos-*-repository` (34 files).
- **D2-6.** `docs/configuration-reference.md`'s `TALOS_RPC_GUEST_ROLE` row
  still said `TALOS_ALLOW_UNSCOPED_DB_SANDBOX` lifts the production boot gate;
  it has not since 2026-10-14.

## Decided

- **The 2026-09-12 shape** for both tables (`20261015130000`): unset
  `app.current_user_id` → permit (engine, sweeps, the bare pool), OR the
  caller's own row, OR a row of one of the caller's orgs. WITH CHECK: unset →
  permit, the caller's own row, or a row of the single active org a write
  scope names (`app.current_org_id`, which `OrgScope` sets with the user).
  `NULLIF(…, '')` on every GUC read. No index added: both tables already have
  `(user_id …)` and `(org_id …)` indexes.
- **Operator decision D2-A — catalog rows (built: visible on `modules`,
  never on `webhook_triggers`).** A `modules` row with `user_id IS NULL AND
  org_id IS NULL` is the shared catalog, public by design (every user lists
  and installs from it), so it stays readable under every scope, guest SQL
  included. It is not writable under a scope: catalog rows are written only by
  the registry sync and the disk seed, on the bare pool. `webhook_triggers`
  has no catalog; a row with neither key is readable by no scoped caller. The
  alternative (catalog rows hidden from guest SQL) was not built: a module
  that may read `modules` at all gains nothing it could not list through the
  catalog tools, and hiding them would break the one scoped reader that counts
  them (below).
- **The assertion is over every policy, not over granted tables.**
  `every_row_security_policy_is_keyed_on_the_user` asks `pg_policies` for any
  policy in `public` whose read condition lacks `app.current_user_id`. Asking
  only of tables granted to `talos_guest` would be vacuous in CI — the role
  ships with no grants — and a grant is one statement an operator makes later.
- **Check 104** (D2-5): scope = every crate whose manifest depends on `sqlx`;
  a bind names THE PARAMETER (`.bind(user_id)`, `.bind(&user_id)`,
  `.bind(Some(user_id))`, or a `query!`-family macro argument); "passing it
  on" counts only into a named scoping helper (`begin_user_scoped`,
  `begin_tenant_read_scoped`, `UnitOfWork::begin_user`, `TenantReadScope::new`,
  `OrgScope::new`) or into another function held to the rule. `--self-test`
  runs in `make test-scripts`.

## Every scoped reader of the two tables (enumerated before the change)

Policies bite only on a transaction that sets `talos_app`; every other
statement on these tables runs on the bare (superuser) pool. The scoped ones:

| Site | Scope (`app.current_org_ids`) | Reads | Changes? |
|---|---|---|---|
| `talos-module-repository` `list_user_pinned_modules` (JOIN `modules` on the caller's `user_id`) | `begin_user_scoped` (empty) | own rows | no |
| `talos-advanced-repository` `list_pinned_modules_with_user_install_status` (EXISTS on the caller's `user_id`) | `user_scoped_tx` (empty) | own rows | no |
| `talos-analytics-repository` `get_system_status_counts` — `modules WHERE user_id = $1 OR user_id IS NULL`, `webhook_triggers WHERE user_id = $1`, the `user_modules` view | `begin_user_scoped` (empty) | own + catalog | no — the catalog arm keeps `user_id IS NULL AND org_id IS NULL` rows |
| `talos-workflow-repository` `list_workflows_paginated` — `EXISTS (… webhook_triggers t WHERE t.workflow_id = w.id …)` under `w.user_id = $1` | `begin_user_scoped` (empty) | triggers of the caller's workflows | no in practice: a trigger's owner is its workflow's owner by construction (`create_webhook` requires `workflow_exists(wf, user)`; every trigger INSERT is on the pool) |
| `talos-rpc-subscribers` `run_guest_transaction` | owner, empty | whatever is granted | **yes — the fix**: the owner's rows (and catalog modules), not every tenant's |

No scoped statement WRITES either table, so the WITH CHECK change affects no
current path. Enumeration by an Explore pass over every scoped-transaction
helper and the statements run on it, re-read here.

## Measured

- Check 104 on main @ 7e267e5f with the new rule: 468 files scanned (was 34);
  first draft 10 hits — 8 false positives, all `sqlx::query!` macros binding
  `user_id` as a macro argument, fixed by the macro rule — then 2 hits, both
  deployment-wide operator acts that pass `user_id` only to record the actor
  (`republish_system_templates_recorded`, `set_execution_paused_recorded`),
  marked with that reason. 0 false positives after the macro rule.

## Tests

- `data_plane_tenancy_db_tests::every_row_security_policy_is_keyed_on_the_user`.
- `data_plane_tenancy_db_tests::guest_sql_sees_only_its_owners_modules` — two
  users each own a module, a catalog module exists, `GRANT SELECT ON modules
  TO talos_guest`; each actor's guest query sees its owner's module and the
  catalog one, never the other tenant's.
- `lint-unbound-user-id.py --self-test` (bound, `&`, `Some`, another struct's
  `user_id`, a scoping helper, `TenantReadScope::new`, an unrelated call, a
  held callee, a `query!` macro with and without `user_id`, the marker, test
  code, a crate without `sqlx`).

Both DB tests are in the `lib-migrated` item R1 added
(`--lib data_plane_tenancy_db_tests`), so CI runs them.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| `modules` read policy keyed on the user | 20260719120000's org-only policy restored on the migrated clone | `guest_sql_sees_only_its_owners_modules`, `every_row_security_policy_is_keyed_on_the_user` | FAIL ×2 / PASS restored (fresh clone of the migrated template) |

## Deliberately NOT done

- No backfill or check of `modules` rows with `user_id IS NULL AND org_id IS
  NOT NULL`: none can be written today (the catalog inserts leave `org_id`
  NULL and the autostamp trigger stamps only user rows); the one theoretical
  source is 20260423040000's backfill from legacy `wasm_modules`. Such a row,
  if any exists, drops out of `get_system_status_counts`' template count
  under a scoped read. `SELECT count(*) FROM modules WHERE user_id IS NULL AND
  org_id IS NOT NULL` answers it on a deployment; not run against the live
  stack from this session.
- `begin_org_scoped` sets `app.current_org_id` but not `app.current_org_ids`,
  so an org-scoped READ of these tables would see only the caller's own and
  catalog rows. No org-scoped transaction reads them today; noted, not
  changed.

## Stated limits

- Check 104 is textual; a function "held to the rule" is matched by name.
