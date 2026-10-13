# A failed run keeps the outputs of the nodes that completed (2026-10-13)

A run failed at its sixth node. `get_node_output` for the five that had
completed answered "Node '…' not found in execution output. Resolved node
labels available: [__trigger_input__]". The only view of what they produced
was the shortened `node_input` lines of the timeline.

## Where the outputs were (measured before deciding)

| Place | Holds completed-node outputs of a failed run? |
|---|---|
| `workflow_executions.output_data[_enc]` | No. The failure finalizer wrote `{"__trigger_input__": …}` or nothing |
| `module_executions.output_data_enc` | Yes, per dispatch, redacted and encrypted. But no node id on the row (two nodes of one module cannot be told apart), nothing for system nodes, and no owner-scoped read by workflow execution |
| `workflow_executions.checkpoint_encrypted` | Only with checkpointing on (off by default); not redacted; no reader for a failed row |
| `execution_events` | No. Input snapshots only, cut to 4 KB |

So they were not stored anywhere a node's output could be served from.

**Why they were lost:** the reactor's results are a map local to the
scheduler loop. A node failure returns `Err` through one of many `?`; a
timeout or a cancellation drops the loop's whole future from outside. Both
drop the map. The caller got a string.

## Decided

* **The engine keeps them.** `VersionedResults` (the loop's map) now has a
  `Drop` that moves the map into a per-engine slot. So it is kept on every
  exit that does not hand the map to a `WorkflowContext`: an error return, a
  timeout, a cancellation. A run that completes or pauses takes the map out
  first (`into_map`) and leaves nothing. A run clears the slot when it
  starts.
  * Why `Drop` and not a line after the loop: a timeout drops the future, so
    no line after the loop runs. The test for the timeout case is the reason
    for the shape.
  * `take_partial_results()` hands the map out ONCE, after the same two
    scrubs a completed run's results pass (the per-run pass rebuilt from the
    engine's node configs, then the stateless patterns).
  * Each engine has its own slot; a sub-workflow's engine is built fresh.
* **The collector stores them**, in the shape a completed run has:
  `failure_output(node_labels, partial, trigger)` keys by label, drops the
  trigger seed and skipped nodes, and redacts. It is pure, so the test runs
  the production projection (the existing success-path test runs a copy).
* **Bounded on their own**, at half the execution-payload ceiling
  (`FAILED_RUN_OUTPUTS_MAX_BYTES`, 5 MiB). The ceiling replaces a whole
  over-size payload with a truncation marker, which would take
  `__trigger_input__` with it, and a retry reads that. Over the bound the
  outputs are left out as a whole (`__completed_outputs_omitted__`: reason,
  node count, bytes, limit). Never a subset.
* **`__trigger_input__` stays at the top level.** Retry, replay and schema
  inference read only that key; none reads node entries of a failed run.
* **Encrypted and owner-scoped exactly as before**: the same
  `mark_execution_failed`, the same `lookup_execution(exec_id, user_id)`.
* **Seven failure paths wired**: `trigger` (the path that was observed),
  replay, `test_workflow_draft`, bulk trigger, trigger-as-actors (these
  stored the trigger already), and `call_workflow` / `test_workflow` (these
  stored nothing, and now store the completed outputs when there are any).
* **`get_node_output`**:
  * also finds an output stored under a node's LABEL when asked by graph id.
    The collector keys by label, so until now a lookup by id failed for any
    node whose label differs from its id, on completed runs too, while the
    error text claimed both worked. One graph read, shared with the
    not-found list;
  * its not-found reply lists nodes only (not `__trigger_input__`) and, for
    a failed run, says what a failed run keeps;
  * its no-output reply for a failed run no longer says a failed run stores
    no outputs.

No N+1: nothing new is read per node. The outputs travel in the one row the
handler already loads.

## Deliberately NOT done

* **Serving from `module_executions`.** No node identity on the row, no
  system nodes, and a new owner-scoped read by workflow execution would be
  needed. The results map already has exactly what a node's output is.
* **The scheduler, webhook, retry, continuation and crash-recovery failure
  paths.** They finalize a failure with no output at all and were left: each
  is a separate call site with its own finalizer, and none was the observed
  path. A scheduled run that fails still stores nothing. Stated in the tool
  description.
* **Returning the completed outputs inline in a failed `test_workflow`
  reply.** They are stored; the reply is unchanged.
* **Reading the checkpoint.** It is not redacted.

## Mutations (more is stored, so the scrub and the bound are guards)

| Mutation | Caught by |
|---|---|
| `failure_output` does not redact | two collector tests |
| the size bound never applies | collector test |
| `take_partial_results` skips both scrubs | engine test |
| `into_map` leaves the map behind (a completed run leaves partial results) | engine test |

Each restored and touched; all pass. The ownership check is unchanged code;
the database test pins it for this read (another user gets "not found or
access denied" and nothing else).

## Tests

* `talos-workflow-engine/tests/partial_results_on_failure.rs` (4), the real
  reactor: a failed run keeps exactly the completed nodes' outputs and gives
  them once; a completed run leaves nothing, and does not see an earlier
  failed run's; a run cut off by its timeout keeps them; what is handed back
  has passed both scrubs.
* `talos-execution-result-collector` (+3, 2 rewritten): the stored shape;
  redaction; the bound, with the trigger kept and the payload under the
  ceiling.
* `controller/tests/failed_run_node_outputs_tests.rs` (1), real rows through
  the real finalizer and the real handler: completed outputs read back by
  label and by graph id, redacted; the failed node's reply; another user
  refused; the trigger still where a retry reads it.
* `talos-mcp-handlers`: the two reply texts and the id-to-label lookup.

Not driven end to end: a failed run through NATS into the finalizer. The
engine hand-over and the stored read are each driven; the join is one call.

## Stated limits

* A node that failed has no entry. A node whose failure was continued past
  has the error envelope it committed.
* Outputs of nodes that were still in flight when the run failed are not
  kept: they had not committed.
* The stored failure payload of a run that completed nodes is larger than
  before (it was the trigger alone). Bounded as above; not measured on the
  reference stack.
