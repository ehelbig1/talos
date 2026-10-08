# Two built-in functions that run SQL they are handed were not on the deny list (2026-10-08)

Module SQL (the `database` world) is read by two gates, the worker's
validator and the controller's re-parse, and both ask one matcher which
functions a statement may not call:
`talos_workflow_job_protocol::is_disallowed_sql_function`. Since 2026-09-10
that list has named the SQL/XML family (`query_to_xml` and its relatives)
because those functions take a query as TEXT and run it, so nothing that reads
the statement can see what the string does.

The same class has two built-in members outside that family, and the list did
not name them: `ts_stat` and the two-argument `ts_rewrite` (text search).

## Measured

Found while measuring the platform-admin `query_paginated` tool
(`2026-10-08-query-paginated-read-only.md`), on a throwaway Postgres from the
pinned image. A statement that names only a table it may read, and calls one
of these two with a string, returned the contents of a different table. Both
gates' recorded verdict for such a statement was "admit, read".

What it reaches depends on the role the statement runs as. Under a role with
no grant on the second table, `ts_stat` was refused by Postgres ("permission
denied for table"); `ts_rewrite` was not tried under that role. Module SQL
gets such a role only when `TALOS_RPC_GUEST_ROLE` is set, and it is unset on
the operator's deployment, where module SQL therefore runs as the pool's role.
That deployment has two `database-node` modules; no catalog template and no
document in this repository uses either function.

## Changed

* `DISALLOWED_SQL_FUNCTIONS` gains `ts_stat` and `ts_rewrite`, and the
  equivalents in two contrib modules that are not installed here
  (`crosstab`, `crosstab2`–`4`, `connectby` from `tablefunc`; `xpath_table`
  from `xml2`), in the same spirit as the `dblink` entries.
* `SQL_TEXT_EVALUATOR_FUNCTIONS` names the members of the list that run
  their text argument, and a test holds every one of them to the deny list.
* Seven statements are added to `talos-sql-classify/corpus/statements.sql`
  and the three snapshots re-recorded. The diff is additions only: both
  gates refuse the six that call a listed function and still admit the
  control (`to_tsvector`).

Mutation: with the two names removed, the list's own test, the worker's
corpus test and the controller's corpus test each fail.

## Stated limits

* **Denied by name.** The three-argument `ts_rewrite` runs no query and is
  refused with the two-argument one: the parsed statement carries no
  argument types to tell them apart.
* **The list is from reading, not from a query.** Postgres records nowhere
  that a function runs its argument. This is every built-in function found
  to do so in the Postgres 17 sources (`xml.c`, `tsvector_op.c`,
  `tsquery_rewrite.c`), plus the two contrib modules. A function a
  deployment installs itself, or one a future Postgres adds, is not covered.
* **So a deny list is not what bounds this class; the role is.** On a
  deployment with `TALOS_RPC_GUEST_ROLE` unset, a function of this kind that
  the list does not name reaches whatever the pool's role can read.

## Deliberately not done

* Setting `TALOS_RPC_GUEST_ROLE` on the operator's deployment: an edit to
  `.env`, and the role has no table grants yet, so the two database modules
  would lose their reads. It is the operator's decision and is listed for
  them.
