# A person's tap can teach the classifier (2026-10-14)

The Smart Classifier learns from human corrections, but a correction could be
recorded only through the operator tools (`ml_resolve_disagreement`,
`ml_append_examples`). `__ml_distill__` appends model labels only. So a
workflow in which the owner taps "this is the right answer" could not turn that
tap into a training label, and kept the confirmed labels as few-shot examples
in actor memory instead.

## Operator decisions (asked and answered 2026-10-14)

* **Wanted now?** Yes: build it.
* **Inside the write ceiling or outside?** Outside, like `__ml_distill__`
  (the 2026-09-06 decision): dataset ingestion that takes the actor id for
  tenancy, not the actor's own data plane. `UNGATED_OUTPUT_PROTOCOLS` already
  names the protocol; nothing new is ungated.

## Decided

* **A field on the existing protocol, not a sibling one**: an `__ml_distill__`
  item (or the single-item form) may carry `"human_confirmed": true`.
  A non-boolean makes the envelope malformed, so it is dropped whole, never
  read as a claim either way.
* **Gold, with the value gold already has**: such an item is appended as
  `source = 'correction'`. Every gold reader (eval's gold slice, knn and LR
  weighting, the teacher audit, the few-shot anchors) keys on that value. A new
  `source` value would need a migration and every one of those readers changed,
  to mean the same thing.
* **The provenance gate**: accepted ONLY when the run's start kind is
  `action_link`. The kind is the engine's word (`__started_by__`, read once from
  the run's own row and carried into child runs; 2026-10-14, item 3), handed to
  the hook as `NodeCompletionContext::started_by_kind` and to the pipeline-step
  hook as a parameter. It is never read from module output. From any other run
  (`schedule`, `manual`, `test`, `webhook`, unknown) the item is **refused**:
  counted, logged (model, count, start kind; never the text) and not appended.
  It is not downgraded to a model label either, because the module asserted it
  was a person's. A model can therefore never label its own output as human.
* **Kept out of shadow accounting**: the shadow stats measure the fast path
  against the TEACHER, so a human item is not predicted or counted there. It
  enters the dataset as gold.
* **The upsert's existing guard** (`ml_examples.source <> 'correction' OR
  EXCLUDED.source = 'correction'`) means a later model label for the same
  `example_key` never overwrites a tapped one.

## What the gate does not prove

That the label is the one the person tapped. The module run by the action link
is the workflow author's code; the gate proves a person started the run, which
is the boundary the brief drew ("accepted only when the run's
`__started_by__.kind` is `action_link`"). The author is trusted to put the
tapped answer in the label, as they are trusted with the rest of the workflow.

## Tests

* `controller/tests/ml_human_confirmed_label_tests.rs`. This is the first
  end-to-end test `__ml_distill__` has had: its own binary, so it owns the
  process-wide `DISTILL_CONTEXT`. It drives the real `ControllerNodeHook`, the
  real distill flow and `DatasetService`, against a migrated clone:
  * a tap's item lands as `correction` and a model item beside it as
    `llm_production`;
  * the single-item form carries the flag;
  * under `schedule`, `manual`, `test` and unknown, the claimed item is
    refused while the ordinary item in the same envelope lands.
* `talos-workflow-engine/tests/started_by.rs`
  `the_node_hook_is_told_the_runs_start_kind_in_a_child_run_too`: the hook gets
  the engine's kind for a parent node and a child-run node, though a module
  output claimed `action_link`.
* `talos-ml` unit tests: the gate for each start kind; parsing in both forms;
  a non-boolean refused.

**Mutation (the gate):** make `admit_human_labels` admit every start kind. The
DB test goes red with "Some("schedule"): a human label was recorded from a run
no tap started". Restored and touched; green.

## Stated limits

* A pipeline step's item carries the run's kind like a node's, but a module
  bound directly to a push (module-bound dispatch, no workflow run) has no
  start kind and cannot record a human label.
* The refusal is a log line, not a counter.
