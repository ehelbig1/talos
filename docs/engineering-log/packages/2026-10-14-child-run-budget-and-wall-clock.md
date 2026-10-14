# A run has a budget for children and a wall clock (2026-10-14)

Security review 2026-10-14, findings **G-2** (High), **G-6**, **G-8**
(Medium) and **G-13** (Low). Package 4 of the review's remediation.

Read before this package: "The workflow-liveness / child-run family" digest
in `docs/engineering-log/DECISIONS.md`. Two of its non-negotiables bound what
was done: a child run gets NO `workflow_executions` row, and a child run is
NOT charged to the actor's hourly EXECUTION budget. Neither was changed.

## The defects, as verified

- **G-2.** Sub-workflow recursion was bounded by depth (16) only.
  `AdapterSet::into_engine_with_graph` checked depth; nothing counted
  breadth. `ensemble(count 10, child = itself)` was accepted by every writer
  except `add_sub_workflow_node` (the cycle walk existed, but only in the
  advisory `validate_workflow`), so one run attempted up to 10¹⁶ child runs,
  eight sub-engines in flight per level, no fuel and no execution row.
- **G-6.** `validate_graph_timeouts` allowed `execution_timeout_secs: 0`,
  which the engine reads as "no wall-clock cap".
- **G-8.** Actor spend caps are admitted when the execution row is created; a
  child run, which has no row, was never asked, and its fuel was charged to
  the child's actor only.
- **G-13.** `max_concurrent_executions` and the execution pause count rows;
  child runs have none.

## Measured

- Stored graphs with `execution_timeout_secs = 0` on the reference stack:
  **0 of 80** (53 declare a value). Refusing `0` at write changes no stored
  workflow.

## Decided

- **One budget per root run (G-2).** `talos_workflow_engine::child_run_budget`:
  an `Arc<AtomicU32>` the root engine makes, carried — the same counter —
  through `AdapterSet` into every sub-engine at every depth, and taken at
  `AdapterSet::into_engine_with_graph` beside the depth guard. That is the
  hydration every sub-workflow handler uses (sub-workflow/ensemble/judge/
  reflective-retry/llm-dispatch via `execute_subworkflow_graph`, dynamic and
  capability dispatch via `run_dispatched_subworkflow`, each agent-loop
  iteration), so there is one place to take it and no handler can skip it.
  Refusal: `WorkflowEngineError::ChildRunBudgetExhausted { limit }` /
  `SubflowError::ChildRunBudgetExhausted`. Default 256,
  `TALOS_MAX_CHILD_RUNS_PER_RUN` 1–10 000 (anything else is the default — a
  typo must not unbound it, and 0 must not wedge every sub-workflow).
- **The root's wall clock reaches every child.** `AdapterSet` carries the
  building engine's published deadline; a hydrated child's timeout becomes
  the smaller of its own and what is left of the parent's, and a child whose
  graph says `0` gets the parent's remainder.
- **Self-reference refused at write (G-2).** `upsert_system_node` — the one
  helper behind every `add_*_node` tool — runs the existing cross-workflow
  cycle walk (`talos_workflow_validation::sub_workflow_cycle_for_write`, i.e.
  `load_child_graphs` + `find_sub_workflow_cycle`) for a node that names a
  child, and refuses before saving. One check covers `A → A` and `A → B → A`
  for every child-reference key (`collect_child_workflow_references`). A failed
  read of the child graphs refuses.
- **`0` refused at write (G-6).** `validate_graph_timeouts` — which GraphQL
  create/update, `import_workflow`, `import_yaml_workflow`,
  `create_workflow_from_spec` and every MCP graph writer that goes through
  `ensure_graph_within_caps` already call — refuses
  `execution_timeout_secs: 0`. The engine
  keeps reading `0` as "no cap" for programmatic callers; a child is bounded
  by its root regardless.
- **Child admission and root charging (G-8).** A new engine port,
  `talos_workflow_engine_core::ChildRunAdmission`, is asked before each child
  run — after its actor binding, so for the actor it runs AS — at all three
  child sites; the controller's `talos_engine::child_run_admission` answers
  from the actor's hourly FUEL cap in one statement
  (`talos_actor_budget_refusal::child_run_fuel_refusal`), records a refusal
  like any refused start, and refuses when the cap cannot be read (spend gate,
  fail closed). Only the fuel cap: the execution-count caps stay out by the
  recorded decision. Each child dispatch also carries `root_actor_id`
  (`DispatchJob` → `FuelReport` → `DispatchFuel` → a new
  `execution_cost_rollup.root_actor_id`, written only by
  `talos_cost_attribution`), and `fuel_last_hour` counts a row once for either
  actor, so the root is charged for spend it moved into children.
- **G-13** is documented, not changed: child runs are bounded by the child-run
  budget and the fuel admission, and are still not counted toward
  `max_concurrent_executions` or stopped by the pause once their root runs
  (`docs/configuration-reference.md`, `TALOS_MAX_CHILD_RUNS_PER_RUN` row).
  Counting them toward the child workflow's own concurrency cap would need a
  process/Redis gauge per workflow — recorded as the follow-up, not built.
- Found while testing: `upsert_system_node_into_graph` silently dropped the
  node when the stored graph had no `nodes` array (`{}`) while the tool
  reported it added. It now creates the arrays.

## One home

- Breadth: `child_run_budget::ChildRunBudget`, taken only in
  `AdapterSet::into_engine_with_graph`.
- Child wall clock: the same function.
- Write-time cycle refusal: `talos_workflow_validation::sub_workflow_cycle_for_write`,
  called from `upsert_system_node`.
- Child spend: `ChildRunAdmission` (port) / `child_run_fuel_refusal` (rule);
  root charging: `fuel_last_hour`'s `actor_id = $1 OR root_actor_id = $1`.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| child-run budget | the take bypassed | `child_run_budget.rs::{a_self_referencing_ensemble_stops_at_the_child_run_budget_not_at_the_depth_guard, a_sub_engine_spends_its_roots_budget_not_a_fresh_one}` | FAIL / PASS restored |
| child wall clock | clamp disabled | `engine_tests::a_child_engine_never_outlives_its_parents_deadline` | FAIL / PASS restored |
| write-time cycle gate | gate skipped | `sub_workflow_cycle_write_gate_tests.rs` (both) | FAIL / PASS restored |
| `0` refused | refusal disabled | `timeout_validator_refuses_zero` | FAIL / PASS restored |
| admission asked | port answered `Ok` without asking | `a_child_run_refused_by_admission_does_not_run` | FAIL / PASS restored |
| child fuel cap | cap ×1000 | `fuel_ledger_tests::a_child_run_is_refused_when_its_actor_has_spent_its_fuel` | FAIL / PASS restored |
| root charged | `root_actor_id` arm removed | `fuel_ledger_tests::a_childs_fuel_is_charged_to_the_root_runs_actor_once` | FAIL / PASS restored |

## Deliberately NOT done

- No child `workflow_executions` row and no execution-count charge for a child
  (recorded decisions; the digest's measured reasons still hold).
- The engine's own reading of `0` is unchanged (tests and tools rely on
  "no cap"); every stored-graph writer refuses it instead.
- No per-workflow concurrency gauge for child runs (G-13's stronger option).

## Stated limits

- The budget is per root RUN: a scheduled workflow that fans out within its
  budget every minute is bounded by the schedule floor and the actor's fuel
  cap, not by this counter.
- Child admission reads recorded fuel; fuel spent by attempts still in flight
  is not yet in the sum (the same lag the root admission has).
- The child's deadline clamp uses the parent's base deadline; time the parent
  spent queued for the local-inference slot (which extends the parent) is not
  added, so a child may be cut slightly early — the conservative direction.
