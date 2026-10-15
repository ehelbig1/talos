# The tenancy backstop where the app layer was the only layer (2026-10-15)

Security review 2026-10-14, package 9: findings **D-1** (Medium), **D-3**
(Medium-Low), **D-4**, **D-5**, **D-6**, **D-8** (Low), and the D-10 coupling
in `memory_read_grants`. D-2 shipped in package 5a; D-7 and D-9 are package 15.

## Measured (read-only, reference deployment and the migrated scratch schema)

- `actor_memory`: 52 rows; 0 with `org_id` NULL; 0 whose `org_id` differs from
  its actor's. The table HAS carried a policy since `20260719120000`, created
  inside a `DO` loop — which is why the review's grep for
  `ALTER TABLE actor_memory ENABLE` found none.
- The five user-keyed integration tables: no policy; each has an index leading
  with `user_id`.
- Repository functions taking `user_id: Uuid` and building a statement: 320; 319
  bind it, 1 passes it on.

## Decided

- **D-1.** Migration `20261015100000`. `actor_memory`'s policy is now
  parent-derived — visible exactly when its actor is (`actors_tenant_isolation`
  decides) — replacing the org-keyed one. That one was worse than latent: it
  read a `begin_user_scoped` transaction's EMPTY org list as "unset" and
  admitted every tenant's rows, so the GraphQL memory listing (the one scoped
  reader) had no effective backstop. `rls_tenant_backstop_tests` drives that
  production reader (`list_memories_with_ciphertext_scoped`, `WHERE actor_id =
  $1` only) as a stranger and as the owner. `plaid_items`,
  `google_health_integrations`, `microsoft_365_integrations`,
  `google_calendar_write_integrations` and `google_cloud_integrations` carry a
  `user_id` policy, and the readers that know the user now run in
  `begin_user_scoped`: the cross-provider connection listing and disconnect
  (`talos_integrations::store`, which reaches all nine provider tables), the
  Google Cloud reads and full-tier consent list, and Plaid's environment read.
  The tables left out, with reasons, are in DECISIONS.md "Row security: which
  tenant tables carry a policy".
- **D-10 (the coupling).** The read-grant expiry sweep runs on the pool, before
  the user's transaction: it deletes every user's long-expired grants, which a
  policy on the table would otherwise have narrowed to one user without a word.
- **D-3.** `talos_workflow_job_protocol::GUEST_EXCLUDED_SQL_FUNCTIONS`
  (`generate_series`, `generate_subscripts`, `lpad`, `repeat`, `rpad`) and
  `is_allowed_guest_sql_function`, asked by the worker's validator and the
  controller's re-check; `query_paginated` keeps the full list. The guest
  transaction sets `statement_timeout` to the RPC budget
  (`QUERY_TIMEOUT_SECS`, 30 s, where the pool default of 60 s let a statement
  run on after the caller had gone) and `work_mem = '4MB'`, in the round trip
  that sets the tenant GUCs.
- **D-4.** `talos_sql_classify::public_table_name` / `first_relation_not_public`
  is the one rule for what caller SQL may read by name — bare or
  `public.`-qualified, not `pg_`-prefixed, no other schema. The worker
  (`SqlValidationError::NonPublicRelation`), the controller's re-check
  (`controller_side_non_public_relation`, counted `statement_not_permitted`)
  and `query_paginated` (whose withheld-table list stays its own) all ask it.
- **D-5.** Every `query_paginated` run writes an `admin_query_paginated` row to
  `admin_event_log`: caller, SHA-256 of the statement (never its text), page,
  row count. A run that cannot be recorded returns no rows.
- **D-6.** `page` is 1..=1 000 000 and the offset is checked arithmetic.
- **D-8. Lint check 104** (`scripts/lint-unbound-user-id.py`): a
  `pub async fn` in `talos-*-repository/src` that takes `user_id: Uuid` and
  builds a statement binds it or passes it on. 0 hits, 0 false positives on
  this tree.

## Corpus

Nine statements added (`statements.sql`); all four snapshots re-recorded. Every
changed verdict is admitted → refused: the five size-building functions, every
`pg_catalog` / `information_schema` / `pg_` / other-schema read, `FROM ONLY`,
`UPDATE ONLY`, `DELETE FROM ONLY`, and the `TABLE` command in guest SQL.

## Operator decision surfaced

- **D-3 (the decision; review finding D-5).** `talos_admin_read` still reads
  every tenant's module source, execution inputs and event log previews.
  Options: column-level grants that withhold `modules.source_code`,
  `module_marketplace.snapshot_source_code`, `workflow_executions(_archive).input_data`,
  `execution_events.log_message`, `semantic_execution_cache.output_json` and
  `integration_state.value` (Postgres needs the table grant replaced by a
  column list, so `SELECT *` on those tables stops working for the tool and
  `admin_read_role_grants` gains a third category); or a second-factor
  assertion, which an MCP token cannot make. Recommendation: the column
  grants. Not built — every call is now recorded, which is the half that needed
  no decision.

## Deliberately NOT done / stated limits

- The bare-pool `talos_memory::*` readers (MCP tools, the memory RPC, the
  engine) still rest on app-layer scoping: moving them is a signature change
  across ~40 functions and the RPC hot path.
- Writes to the integration tables were not moved into a scoped transaction;
  each binds `user_id`, and `WITH CHECK` would only add a refusal for a writer
  that already filters.
- Check 104 cannot see a neutered bind (`OR $n IS NULL`), a bind under another
  name, or whether a callee that is handed `user_id` binds it.
- `query_paginated`'s record is a row in `admin_event_log`, which
  `query_paginated` itself withholds; it is not the hash-chained ledger.

## Mutation proof

See the PR body.
