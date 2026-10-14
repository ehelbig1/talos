# A child run keeps the outer trigger the engine gave it (2026-10-14)

A `sub_workflow` node merged the parent run's `__trigger_input__` into its
child's trigger seed, "so the scaffold's always-preserved contract survives
sub-workflow composition". `dispatch_subworkflow` then removed every key that
starts with `__` from that seed, that one included.

## Reproduced

`talos-workflow-engine/tests/sub_workflow_trigger_input.rs`, on `main`:

* `trigger → module → sub_workflow`: the child's module received the
  upstream module's output as `__trigger_input__`. **Failed.**
* Three levels, each `sub_workflow` node after another node: the grandchild
  received its own upstream's output. **Failed.**
* A loop node inside such a child: each iteration received the child's seed
  (the upstream output). **Failed.**
* A ROOT `sub_workflow` node: correct, because its upstream IS the trigger.
  This is why the ticket-start → gap-report chain worked. **Passed**, before and
  after.

## Found, and it narrows the brief

**A module could not forge `__trigger_input__`, before this change or after
it.** The engine strips the engine-authored input keys, `__trigger_input__`
among them, from every module's committed output (`apply_output_protocols`,
`engine_completion.rs`). A module upstream of a `sub_workflow` node or a loop
node therefore never had a way to author the key. The defect was that the real
value was lost, not that a forged one got through. The loop node's first
source, `inputs["__trigger_input__"]`, was dead code for the same reason.

## Decided

* **One carrier: an engine parameter.** `ParallelWorkflowEngine::outer_trigger_input`
  is set by the `sub_workflow` dispatcher on the child engine before it runs
  (`run_subworkflow_graph`). `extract_trigger_input` returns it when it is set,
  and otherwise the run's own `__trigger__` seed. Every level passes on what it
  was given, so a grandchild sees the top-level run's trigger.
* **No `__trigger_input__` in any seed.** A child's seed is now stripped of
  every engine-authored input key, `__trigger_input__` included.
  `strip_engine_authored_keys_for_child_seed` (the one exception) and
  `extract_trigger_input`'s unwrapping of a `__trigger_input__` key out of a
  seed are deleted, because nothing writes that wrapper any more. The key stays
  engine-authored end to end: set by the engine when a node is dispatched, and
  stripped at the inbound trigger, at a child's seed and at every module output.
* **The loop node asks the engine** (`extract_trigger_input`), like the
  single-node, `for_each_connection` and `sub_workflow` paths do. Inside a
  child, its old fallback would have returned the child's seed.
* **A root child sees what the parent's own nodes see**: the parent's trigger
  as stored. Before this change it saw the trigger minus every `__` key. The
  engine-authored keys were already gone at the inbound strip, so the difference
  is limited to any other `__` keys a caller put in the trigger.

## The other kinds that build a child trigger (checked, not changed)

`judge`, `ensemble` (candidates and its judge), `reflective_retry` (the child
and the reflection), `llm_dispatch` (classifier, route, fallback), `dispatch`,
`capability_dispatch` and the agent-loop body do **not** have this shape. None
of them merges a parent trigger into the seed. Each strips `__` keys from its
inputs, or wraps them under `content` / `input`, and hands the result to the
child as its seed. Their children's `__trigger_input__` is therefore that seed:
a judge's `{content, rubric}` and a classifier's input, which the existing
workflows are written against.

Giving them the outer trigger instead would break a judge module that reads
`__trigger_input__.content`, so they are not changed. If a judge or classifier
ever needs the outer run's trigger, the answer is to pass
`outer_trigger_input` beside its seed. It should not replace the seed.

## Mutations (reserved key)

* **M1.** Remove the module-output strip in `apply_output_protocols`, so the
  forged key reaches the dispatcher. The four tests stay **green**: the
  parameter holds on its own.
* **M2**, on top of M1. Take the child's trigger from the gathered inputs'
  `__trigger_input__` (what the module wrote). **Three red.**
* **M3.** Restore the loop node's own read. **The loop test goes red.**
* All restored and touched; all four green.

## Tests

`sub_workflow_trigger_input.rs` (4). Whole suites green:
`talos-workflow-engine` (all features), `talos-workflow-engine-core`.

## Stated limits

* A child started by `test_subworkflow_contract`, or by any caller of the
  public `execute_subworkflow_graph`, gets no outer trigger. Its
  `__trigger_input__` is its seed, as before.
