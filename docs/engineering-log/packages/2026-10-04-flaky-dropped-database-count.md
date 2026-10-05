# The one flaky test: a count compared across an eviction

2026-10-04

`entries_from_a_dropped_database_are_counted_and_disclosed`
(`controller/tests/statement_stats_tests.rs`) failed in CI for the third
time, on a pull request that changed only a workflow file. Each failure
costs a re-run of about twenty minutes. Of 58 recent pull-request runs, 3
failed, and this test is the one flaky test on record.

## The failure

```
before=2155 after=2069
before=2188 after=2120
```

The test reads the report's `entries_for_dropped_databases`, mints a
statement in a new database, drops the database, reads the count again and
asserts it rose. It fell, by 86 and by 68.

## The cause, reproduced

The count is cluster-wide and lives under one shared cap
(`pg_stat_statements.max`, 5000 by default). In CI every test's database
clone mints entries against that cap. When the instrument is full, Postgres
evicts its least-used entries in a sweep. A sweep between the two readings
removes more dropped-database entries than the test adds.

Reproduced on a throwaway Postgres started with `pg_stat_statements.max=100`,
running the whole test binary six times:

* the old test failed in three of six runs, with `before=40 after=39` — the
  same shape as CI;
* the rewritten test printed, for the windows it declined to compare,
  `1 eviction sweep(s) between the readings (before=72 after=63)`: the count
  falling in exactly the windows where the eviction counter advanced.

## The fix

The report already says when an eviction happened (`coverage.entries_evicted`).
The test now reads it with each count, and makes its claim exactly: in a
window with NO eviction, an entry minted by a database that is then dropped
raises the count. A window that saw an eviction proves nothing either way and
is taken again, up to eight times, with a line saying so. If every window saw
one, the test fails and says that — it never passes on a comparison it could
not make.

On the cap-100 cluster the rewritten test passed in every one of eight full
runs and ten runs alone.

## Stated limits

* On that same hostile cluster three OTHER tests in the binary failed
  intermittently (`a_statement_from_another_database_is_not_in_this_databases_report`,
  `text_postgres_withheld_is_reported_as_withheld_not_as_the_statement`,
  `a_planted_ansi_escape_in_an_alias_does_not_survive_into_the_report`). Each
  plants a statement and reads it back; a sweep in between evicts it. None
  has failed in CI, where the cap is fifty times larger, and they are not
  changed here. They have the same exposure in principle.
* Raising `pg_stat_statements.max` in the integration runner would remove
  the cause for all of them. Not done: how many entries one shard mints is
  not measured, so any number would be a guess. It can be read from
  `coverage.entries_cluster` at the end of a shard.
