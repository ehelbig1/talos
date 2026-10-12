# An edge condition that errors is told apart from one that is false (2026-10-12)

An edge was given the condition `hold.held == true`. An edge condition's
scope is its source node's output FIELDS (`held`), so `hold` was unbound and
the expression errored. An edge whose condition errors is not taken. The
downstream node never ran, the run was `completed`, `test_workflow` said
`passed: true`, `add_edge` had accepted the condition and `validate_workflow`
said nothing.

## Not changed, on purpose

**A condition that errors still means "branch not taken".** That rule is
recorded in `condition_eval.rs` and in package EU (2026-09-25) and stays:
failing the run on a bad expression would take down a workflow over one
typo. What was missing is telling anyone it happened. The counter
(`talos_condition_eval_failures_total{kind="edge_condition"}`) and the WARN
already existed; neither carries an execution id, a node or the edge.

## Decided

**At run time**

* `resolve_edge` now calls `eval_condition` and keeps the error. The edge
  resolves inactive either way.
* **The record is an engine-authored key on the SOURCE node's committed
  output**, `__edge_condition_errors__`:
  `[{target, condition, error}]`, at most 16 entries, the two strings cut at
  240 bytes, sorted by target, the error DLP-scrubbed.
  * On the source because that is the output the condition was evaluated
    against, and because a node's output is already what every surface
    stores and shows (`get_node_output`, `get_execution_output`, the stored
    `output_data`, `test_workflow`). No persist site changed.
  * Not on the skipped child: `project_engine_results_to_output` drops a
    skipped node, so a record there would not reach a test result; and a
    child with a second, live edge is not skipped at all.
  * Set-or-REMOVE. Whatever a module returns under the key is removed when
    the node's successors are released, before any condition is evaluated.
  * Absent when every condition evaluated. A condition that evaluates
    `false` leaves the output byte-identical to before.
  * A source whose output is not a JSON object has nowhere to carry the key;
    that case logs `edge_condition_errors_unrecorded` and is not recorded.
* **`test_workflow` lists them** as `edge_condition_errors:
  [{source, target, condition, error}]`, and a run that has one is
  `passed_with_failures` with `passed: false`. `allow_continued_failures`
  does not excuse it: no test means to exercise an expression that cannot be
  evaluated.
* **`get_execution_status` lists them** in both modes, when there are any.

**At authoring time**

* `talos_engine::rhai_helpers::unbound_condition_variables(condition,
  context)` asks the real evaluator against the real scope
  (`build_condition_scope`, the one `test_condition` reports). On "variable
  not found" it records the name, binds it to an empty map and evaluates
  again, up to 8 names. No second scope builder, no parse of an error string.
* **The warning is for a variable that is the name of a node**
  (`edge_condition_names_a_node`): any node id or label of the graph.
  `add_edge`, `add_edge_to_workflow` and `validate_workflow` (category
  `edge-condition`) all call it. Never a rejection.
* **`talos-workflow-validation` now depends on `talos-engine`**, to ask the
  one scope builder. `talos-engine` does not depend on it; the two crates
  that depend on validation and did not already link the engine
  (`talos-workflow-versions`, `talos-hot-update-service`) are controller-side.

## Deliberately NOT done

* **Warning on every unbound name.** Against an empty output every field a
  source really returns is unbound, so that warns on every conditional edge.
  `dry_run_skip_condition` does this for skip conditions, where the default
  is fail-open; for an edge the precise case was chosen instead.
* **Evaluating the condition against the source's last recorded output.** It
  would catch a misspelt field (`hled == true`) where history exists. It
  needs a read on the authoring path and there is no such read today. The
  run-time record covers that case the first time the workflow runs.
* **A run-level list on `WorkflowContext`.** Eight or more places persist a
  run's output; each would have to write the list.
* **Changing the skip envelope** of the child.

## Stated limits

* The probe sees the names evaluation REACHES: `a || hold.x` with `a` true
  never reads `hold`.
* A node label that is also a real top-level field of the source's output is
  warned about wrongly; the message says so.
* A skip condition, a loop condition and a verify condition are unchanged:
  only edges are recorded.
* A child sub-workflow's errored edges are on the child's node outputs, not
  listed for the parent run.
* The other children of a source node now receive the key in their input
  when one of that node's conditions errored. Never otherwise.

## Tests

* `talos-workflow-engine/tests/edge_routing.rs`: an errored condition is not
  taken AND recorded on its source, beside a sound edge that is taken; a
  false condition leaves the output byte-identical; a module-authored copy
  of the key is removed.
* `talos-mcp-handlers/tests/edge_condition_errors.rs`, with the production
  Rhai evaluator: `hold.held == true` is found by the validator, not taken
  by the engine, recorded with `Variable not found: hold`, and the report
  does not pass, while the status-only judgement that used to be `passed`
  says true over the same output. `held == true` runs the target and records
  nothing; `held == false` is not an error.
* `unbound_condition_variables`: the observed case, order, the always-bound
  names, another kind of failure, the bound.
* `talos-workflow-validation`: the finding and its message, sound conditions
  not reported, labels count, `validate_prepared` raises it, the run-record
  reader, the verdict.

**Mutations** (the key is engine-authored, so both were run):

| mutation | caught by |
|---|---|
| the record is never written | `an_edge_condition_that_errors_is_recorded_on_its_source_node`, and the end-to-end test |
| a module's own copy of the key is not removed | `a_module_cannot_author_the_edge_condition_error_record` |

## Depends on

The `test_workflow` verdict from
`2026-10-12-test-workflow-names-continued-failures.md` (PR 1222).
