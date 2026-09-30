# 2026-09-30 — the fuel-headroom query no longer joins per rollup row

**Found** in `pg_stat_statements` after the 2026-09-29 fuel deploy:
`get_node_fuel_headroom` ran at 126–164 ms (mean 38.9 ms over 1 211 calls,
max 170 ms) against the ~24 ms its 2026-09-10 rewrite measured. The query
feeds the controller's high-utilisation gauge every 300 s (fleet-wide) and the
fuel report (owner-scoped).

**Cause, measured by `EXPLAIN (ANALYZE, BUFFERS)`, read-only.**
- `execution_cost_rollup` had **no planner statistics** for its `outcome`
  column (added by migration `20260929120000`). The table has never been
  auto-analyzed in the current statistics period: `n_mod_since_analyze`
  6 472 against an autoanalyze threshold of ~6 712 (50 + 0.1 × 66 618).
- So the planner estimated the window scan at **175 rows; it returned
  36 279**. It then chose a nested loop that probed `workflow_executions` once
  per rollup row to read `is_test_execution`: 36 258 index probes and
  108 699 buffer hits, to exclude rows from **10** test executions.

**Decided.**
- The test exclusion is `r.execution_id NOT IN (SELECT id FROM
  workflow_executions WHERE is_test_execution)`. This is a hashed subplan
  over the partial index `idx_workflow_executions_test`, computed once per
  call. `NOT IN` is exact because both columns are NOT NULL. A row with no
  execution row (a sub-workflow run) still reads as "not a test", the same
  LOUD direction as before.
- The owner filter is `$2 IS NULL OR r.workflow_id IN (SELECT id FROM
  workflows WHERE user_id = $2)`. Under `OR` the sublink cannot be pulled up
  into a join, so it is also a hashed subplan, and the per-row `workflows`
  join is gone. The workflow name is still joined after the aggregate, which
  still drops a pair whose workflow was deleted.
- `r.workflow_id IS NOT NULL` excludes module-bound rows (possible since the
  2026-09-29 fuel migration) before the aggregate rather than after it.
- **Neither plan choice depends on the rollup's row estimate.** That is the
  point: statistics will go stale again after the next column is added.

**Measured**, on the dev database with the same stale statistics, 70 identical
rows in both forms (checked in both directions with `EXCEPT`):

| form | before | after |
|---|---|---|
| fleet-wide | 53.9 ms | 25.1 ms |
| owner-scoped | 51.6 ms | 23.9 ms |

**Deliberately NOT done.**
- **No `ANALYZE`**: it is an operator action on the only environment, and
  autovacuum will analyze the table on its own within about a day at the
  current write rate. Recorded rather than run.
- **No migration running `ANALYZE`**: it would be stale-proof only until the
  next migration, and the query no longer depends on it.
- **No index**: the 2026-09-10 argument stands (at 48% window selectivity the
  seq scan is the right plan).

**Proof.**
- `talos-analytics-repository/tests/fuel_headroom.rs` (`ci-store: migrated`)
  is the first behavioural test of this query. It drives the real method
  against a migrated Postgres. It asserts:
  - a sub-workflow row is counted; a test execution, a failed attempt and a
    module-bound row are not;
  - the ceiling is the latest row's;
  - owner scoping returns only the caller's workflows, and the fleet-wide
    form returns both.
- The source pin is updated to the new shape.
- Check 88 PREPAREs all 1 246 static statements.
- **Mutations: 2 applied, 2 caught.** One drops the owner filter (tenancy);
  the other drops the test exclusion.
