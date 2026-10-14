# A child run can be found and looked into, however deep it ran (2026-10-14)

Workflow A runs B as a sub-workflow node, and B runs C (a ticket start → a gap
report → a build brief). `list_executions` for B or C showed none of those
runs, and whether C's notification node ran had to be inferred from the memory
C wrote.

## Found

* **C's node outputs were stored nowhere.** A sub-workflow node receives its
  child's COLLAPSED output: with one terminal node, that node's output and
  nothing else. Every other node output of the child, and everything a
  grandchild did, was dropped with the child's engine. `get_sub_workflow_output`
  showed B's nodes only because B has two terminal nodes, which makes the
  collapse fall back to a label-keyed map of every node.
* **A grandchild's ledger row named no real execution.** A child engine runs
  under a synthetic execution id (`Uuid::new_v4()`) that names no row. A
  direct child's `sub_workflow_runs.parent_execution_id` is the real parent
  execution; a grandchild's was the child's synthetic id. Nothing could trace
  C's run back to the run it belonged to.
* **So the retention purge purged a pinned run's grandchildren.** Its
  pinned-parent exemption looks `parent_execution_id` up in both execution
  tiers; for a grandchild that never matched.
* **The brief is partly out of date: the SLA report and readiness already
  count child runs.** RFC 0012 P2 taught `get_workflow_sla_report`
  (`talos-analytics-repository/src/sla_window.rs`, `success_rate.child_runs`)
  and the readiness scorers to read `sub_workflow_runs`. `get_workflow_stats`
  and `list_executions` do not.

## Decided

* **A child run's node outputs are kept in the PARENT execution's stored
  output**, under the engine-authored top-level key `__child_runs__`, beside
  `__node_timings__`. Same row, same encryption at rest, same retention, same
  ownership check, same DLP pass as the parent's own node outputs. Not in any
  node's output, so no downstream node receives it and no node payload grows.
* **The ledger still holds no payload** (RFC 0012's decision stands). It gains
  two value columns, `root_execution_id` and `node_path`, so a row names the
  top-level execution and the path to read the run by. No backfill: a
  grandchild's root cannot be derived from what an old row holds.
* **The record nests as the runs nest**: `{<node>: {runs: [{workflow_id, kind,
  status, nodes, child_runs}], runs_not_kept}}`, where `child_runs` is the
  child engine's own record. One home: `talos_workflow_engine::child_run_outputs`.
  Every site that hydrates a child engine (`execute_subworkflow_graph`,
  `run_dispatched_subworkflow`, the agent-loop body) keeps outputs through the
  same `ChildRunReporter::keep_outputs` and stamps the child's lineage from the
  same `ChildRunReporter::child_lineage`, so all nine dispatch kinds are kept.
* **Bounds.** At most 8 runs per node (the newest; `runs_not_kept` counts the
  rest) and 1 MiB of kept outputs per engine. A run over the bound keeps its
  metadata and says `outputs_omitted: {reason: "too_large", bytes}` — never a
  subset of its nodes. The collector adds the record only when the whole
  stored output still fits the 10 MiB execution-payload ceiling; otherwise
  `__child_runs__` is `{__omitted__: {...}}`. The ceiling replaces an over-size
  payload WHOLE, so a record that pushed a payload over it would have cost the
  run the outputs it stored before this change.
* **A failed child keeps what its completed nodes committed** (its engine's
  `take_partial_results`, already scrubbed), status `failed`. A failed parent
  run keeps its record too (`collect_failure_output`, `keep_failed_run_outputs`).
* **`get_sub_workflow_output` takes `path`** (node ids, outermost first,
  1..=16, the engine's default nesting limit). An intermediate step follows
  the node's NEWEST run, which is the run whose output the parent received.
  The answer names the next level's child runs rather than inlining them. The
  ownership check is the same `lookup_execution(exec_id, user_id)` the
  `node_id` form makes, so another user's run reads word for word as a run
  that does not exist. `node_id` alone behaves as before and, when a record
  exists, adds one line saying how to read every node.
* **`list_executions(include_child_runs: true)`** adds a separate
  `child_runs` list (one page query, one count query, `child_workflow_id`
  index; no lookup per parent), each item `kind: "child"` with the top-level
  `execution_id` and `path` to pass to `get_sub_workflow_output`. Paged with
  the same limit and offset, independently of `executions`. Not interleaved,
  so `count`, `total` and `has_more` mean exactly what they meant.
* **Every completion writer stores the record**: the shared collector
  (trigger, retry, replay, continuation, handoff, failure paths), the
  scheduler, the five inline builders in `talos-mcp-handlers/src/workflows.rs`,
  `enqueue_workflow`, both webhook paths, crash recovery and the GraphQL
  trigger.

## The operator's decision

**Should a workflow's child runs count in its stats, SLA and readiness by
default, or only when asked?**

* SLA and readiness ALREADY count them by default (RFC 0012 P2), with the
  ledger's floor disclosed. Changing that is not proposed.
* `get_workflow_stats` does not count them at all.
* `list_executions` lists them only when asked (`LIST_CHILD_RUNS_BY_DEFAULT =
  false` in `talos-mcp-handlers/src/executions.rs`).

Options for the two that remain: (1) leave both as built — opt-in listing, no
child runs in stats; (2) list by default with the `kind: "child"` mark, and give
`get_workflow_stats` a separate `child_runs` block (never folded into its
execution counts, which 161 of 163 readers of `workflow_executions` assume are
top-level runs); (3) fold them into the stats' totals.

**Recommendation: (2).** Listing by default is one constant; the listing keeps
its own list and changes no count. Folding (3) is the double-count the
2026-09-05 decision measured and rejected. Nothing in (2) is built beyond the
constant, pending the answer.

## Deliberately NOT done

* **A child `workflow_executions` row.** Rejected 2026-09-05 with
  measurements; nothing here changes them.
* **Payload in the ledger.**
* **Inlining the whole nested tree in one answer.** A path names one run;
  its children are named, one more path element away.
* **Choosing among a node's earlier runs by index in a path.** At the last
  step every kept run is returned; in the middle the newest is followed.
* **A `node_id` form that walks a scheduler run's output.** The scheduler keys
  a run's node outputs by engine UUID, not label, so `node_id: "assess"` does
  not find them there; this predates the change. The `path` form reads
  `__child_runs__`, which is keyed by label on every path.

## Stated limits

* Runs that started before this change have no record and no path; for a
  direct child the listing derives the path from `parent_node_id`. A
  grandchild row written before it has neither, and says so (`execution_id`
  and `path` are null).
* A run that pauses (an approval, a wait node) and resumes keeps only the
  child runs dispatched after the resume: a resumed run is a new engine, and
  the checkpoint carries node outputs, not the record. A child re-run by crash
  recovery is recorded afresh.
* `__child_runs__` grows a stored output by at most 1 MiB (plus run metadata),
  and only for a run that dispatches a child.

## Tests

* `controller/tests/child_run_outputs_tests.rs` (migrated clone): A → B → C,
  where C has two nodes, run by the real reactor with the real ledger
  recorder, stored by the real collector and repository, read by the real
  handlers. Both of C's node outputs come back through `path: ["assess",
  "brief"]`, redacted; B's come back one level up, naming `brief` as a child
  run; a wrong step names what did run a child there. Another user gets the
  response a nonexistent execution gets, compared whole. `list_executions`
  lists C's run with the top-level execution id (not B's synthetic one),
  `path: ["assess","brief"]`, `depth: 2`, and that pair reads back the run;
  without the flag the envelope has no `child_runs`. A pinned run's
  grandchild survives the ledger purge.
* `talos-workflow-engine/src/child_run_outputs.rs` unit tests: every node
  kept; newest 8 runs per node; a run over the byte bound keeps metadata and
  no subset; an evicted run gives its bytes back BEFORE the next run is
  measured (this test failed on the first version, which measured first).
* `talos-execution-result-collector` unit tests: the path walk (reach, wrong
  step, no record, bad path, too long); a record that would push a payload
  over the ceiling is left out and the payload stays under it; a record that
  fits is redacted.
