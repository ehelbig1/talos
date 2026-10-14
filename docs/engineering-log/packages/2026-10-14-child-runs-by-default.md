# Child runs are listed by default, and stats give them their own block (2026-10-14)

The operator's answer to the decision `2026-10-14-child-run-outputs.md` left
open: should a workflow's child runs (its runs as another run's sub-workflow,
judge, ensemble, dispatch or loop body) be listed and counted by default?

**Decided (operator, 2026-10-14): list them by default, and give the stats a
separate block.** Option (2) of that record. Folding them into the execution
totals (option 3) stays rejected: 161 of 163 readers of `workflow_executions`
assume a row is a top-level run, which is the double count measured on
2026-09-05.

## The change

* **`list_executions` lists child runs by default**
  (`LIST_CHILD_RUNS_BY_DEFAULT = true`). They stay a separate `child_runs`
  list beside `executions`, each `kind: "child"` with the top-level
  `execution_id` and `path`; `count`, `total` and `has_more` mean what they
  meant. `include_child_runs: false` leaves the list out.
* **`get_workflow_stats` gains a `child_runs` block** over the same `days`
  window: `{kind, runs, completed, failed, success_rate_percent,
  avg_duration_secs, last_started_at, covered_from, window_partially_covered,
  note}`. It is never added to `total` / `succeeded` / `failed`. One statement
  (`ChildRunLedger::window_stats_for_child`).
* **UNKNOWN is not zero** (the ledger's rule): an unreadable ledger, or one
  with no rows at all, renders `runs: null` with
  `measurement: {complete: false, reason}`, and the read failure is logged as
  `report_field_not_measured`. A window that starts before the ledger's first
  row says so (`window_partially_covered: true`, `covered_from` = the first
  row). No runs is `runs: 0` with a null rate, never a 0 % rate.

## Not done

* **`get_all_workflow_stats`.** It lists only workflows that have execution
  rows in the window (`HAVING COUNT(we.id) > 0`), so a workflow used only as a
  child is not in it at all. Adding a child block there means changing which
  workflows it lists and how it ranks them, which is a change of its own. The
  per-workflow tool is the one this decision named.
* SLA and readiness: unchanged. They already count child runs (RFC 0012 P2).

## Tests

* `controller/tests/child_run_outputs_tests.rs`: the grandchild workflow's
  `list_executions` carries `child_runs` without being asked, and
  `include_child_runs: false` leaves it out. Its `get_workflow_stats` has
  `total: 0` and `child_runs: {kind: "child", runs: 1, completed: 1,
  failed: 0}`.
* `talos-mcp-handlers` `child_runs_block_tests` (4): a covered window; a
  window older than the ledger; no runs is zero runs and no rate; unreadable
  and empty ledgers are null with a reason.
