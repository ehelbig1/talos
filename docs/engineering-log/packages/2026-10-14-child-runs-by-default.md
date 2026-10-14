# Child runs are listed by default, and the stats give them their own block (2026-10-14)

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

## Across all workflows

* **`get_all_workflow_stats` lists and ranks child runs too** (operator, same
  day). It listed only workflows with execution rows in the window
  (`HAVING COUNT(we.id) > 0`), so a workflow used only as a child was not in it
  at all. Now:
  * each row carries its own `child_runs` block, apart from its totals;
  * rows are ranked by failures of either kind, then runs of either kind, so a
    child-only workflow is listed (with `total: 0`);
  * both reads (the execution summaries and one grouped ledger read,
    `ChildRunLedger::window_stats_by_workflow`) take up to 500 rows (one
    user's workflows) and the merge truncates to 50 after ranking, so no
    workflow reads as "no runs" because it fell past one list's cut.
  * Unknown is not zero here either: an unreadable or empty ledger, or a
    ledger read that hit its cap, makes every row's `child_runs` null and the
    top-level `child_runs` says why. A child-only row past a capped execution
    read is `total: null, executions_unknown: true`.
* SLA and readiness: unchanged. They already count child runs (RFC 0012 P2).

## Tests

* `controller/tests/child_run_outputs_tests.rs`: the grandchild workflow's
  `list_executions` carries `child_runs` without being asked, and
  `include_child_runs: false` leaves it out. Its `get_workflow_stats` has
  `total: 0` and `child_runs: {kind: "child", runs: 1, completed: 1,
  failed: 0}`.
* the same test: `get_all_workflow_stats` lists the grandchild workflow (no
  executions of its own) with `total: 0, child_runs.runs: 1`, and the
  top-level workflow with `total: 1, child_runs.runs: 0`.
* `talos-mcp-handlers` `all_workflow_stats_merge_tests` (3): a child-only
  workflow is listed and four child failures outrank one execution failure;
  unknown is null, never zero; at most 50 rows.
* `talos-mcp-handlers` `child_runs_block_tests` (4): a covered window; a
  window older than the ledger; no runs is zero runs and no rate; unreadable
  and empty ledgers are null with a reason.
