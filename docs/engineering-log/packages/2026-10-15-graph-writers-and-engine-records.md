# Graph writers refuse a self-reference and a reserved node id; the lints see every spelling (2026-10-15)

Security review 2026-10-15 (round 2), findings **G2-2**, **G2-3**, **G2-4**,
**G2-5** (Low), **G2-6** (Info) and the **G-7** follow-through. Package R6 of
the round-2 remediation.

## The defects, as verified

- **G2-2.** `sub_workflow_cycle_for_write` was called only by
  `upsert_system_node` (the `add_*_node` tools). `update_node_config`'s merge
  drops `__` keys only, so `{"child_workflow_id": <self>}` reached the stored
  graph; so could an import or GraphQL `updateWorkflow`. Each trigger then spent
  the run's whole child budget before failing.
- **G2-3.** `check-graph-writers.py` matched `INSERT INTO workflows` /
  `UPDATE workflows` in one spelling; lowercase, `public.`, quoted,
  `UPDATE ONLY` and `MERGE` passed with no finding (no live writer used them —
  re-measured case-insensitively: the widened patterns find no new statement).
- **G2-4.** `lint-world-hint.py` (check 99) exempted every line after a file's
  first `#[cfg(test)] mod`. In `talos-workflow-engine-nats/src/dispatcher.rs`
  the first test module is at line 1460 and the production `JobRequest`
  literal that carries the hint is at 1886 — unscanned.
- **G2-5.** A node id `__child_runs__` was legal, and `attach_child_runs`
  returned early with no record, so a node so named (or so labelled — the
  collector keys outputs by label) stood in the stored output as the
  engine-authored child-run record; `__node_timings__` the same when no timing
  was taken.
- **G-7.** `validate_workflow` did not warn on an `expression_dispatch` node
  without `targets` (the recorded decision: warn now).

## Decided

- **G2-2:** `talos_workflow_repository::graph_caps::refuse_self_reference(graph_json,
  workflow_id)` — pure, over every child-workflow reference
  (`collect_child_workflow_references`) — in front of every statement that
  REWRITES a workflow's graph: `update_workflow_scoped`,
  `update_workflow_graph_json`, the `upsert_workflow_graph_by_name` update
  branch and `write_workflow_graph_if_unchanged` (`update_node_config`'s
  path). An INSERT writes a new id no node can name, so it is not asked there.
  `check-graph-writers.py` now requires it in front of every UPDATE / MERGE of
  the column. Not done: the multi-hop cycle (`A → B → A`) at the generic
  writers — it needs the other workflows' graphs, a database walk per write;
  `add_*_node` keeps the full walk, `validate_workflow` reports a cycle, and
  the child budget bounds a run. The self-reference is the cheap, certain case.
- **G2-3:** both patterns case-insensitive; the table may be `public.`-qualified
  and quoted (`"workflows"`, or `\"workflows\"` inside a Rust literal);
  `UPDATE ONLY` and a `MERGE INTO workflows … SET graph_json` arm; a self-test
  case per spelling.
- **G2-4:** only the brace-matched span of each `#[cfg(test)] mod` is exempt;
  `--self-test` holds a hint-less literal after a test module. Confirmed: the
  literal at `dispatcher.rs:1886` is scanned now (it carries the hint; 0
  findings). Check 106 (`lint-compile-gate.py`, R4) was written with the same
  span rule.
- **G2-5:** a node id beginning with `__` is refused at every writer —
  `graph_caps::refuse_over_cap_graph`, the rule every `graph_json` statement is
  already behind — and by `validate_node_ids` for the early message. Not refused
  at LOAD: a stored graph with such an id would stop running; none can be
  written now. In the stored output, `__child_runs__` and `__node_timings__`
  are set-or-REMOVED (`__trigger_input__` was already written last).
- **G-7:** `validate_workflow` warns (`dispatch-targets-undeclared`) on an
  `expression_dispatch` node whose `data` declares no `targets`. A refusal on a
  date is the operator's call.
- **G2-6 (documented, not changed):** an actor's child-run admission
  (`talos-actor-budget-refusal/src/admission.rs`) refuses whenever the budget
  is used, even under `on_budget_exceeded: "alert"`, where the ROOT run is only
  alerted. Fail-closed, so not a vulnerability; an operator who chose `alert`
  to keep a flagship running will see its sub-workflows refused while the root
  starts. Honouring the mode for children is a policy decision, recorded here
  for the operator.

## Tests

- `graph_caps::tests::a_node_id_beginning_with_two_underscores_is_refused`,
  `…::a_graph_naming_its_own_workflow_as_a_child_is_refused`.
- `controller/tests/graph_writer_gates_tests.rs`:
  `a_node_naming_its_own_workflow_as_a_child_is_refused_by_update_node_config`
  (refused, stored graph unchanged; another workflow is accepted),
  `a_node_id_naming_an_engine_record_is_refused_at_write` (an import creates
  nothing). The first FAILS with the `refuse_self_reference` call removed from
  `write_workflow_graph_if_unchanged`, and passes restored.
- `talos-execution-result-collector`:
  `a_node_output_under_the_record_key_is_never_kept_as_the_record`.
- `talos-workflow-validation`: `an_expression_dispatch_without_targets_is_warned_about`.
- `check-graph-writers.py --self-test` (every spelling; an UPDATE without the
  self-reference rule), `lint-world-hint.py --self-test`.

## Stated limits

- The lints stay textual.
- The multi-hop cycle at the generic writers (above).
