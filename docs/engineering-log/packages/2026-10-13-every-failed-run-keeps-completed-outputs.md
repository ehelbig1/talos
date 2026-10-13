# Every failed run keeps the outputs of the nodes that completed (2026-10-13)

The change that made a failed run keep its completed nodes' outputs wired the
paths that already stored something on failure (trigger, replay, the draft
test, bulk trigger, trigger-as-actors, `call_workflow`, `test_workflow`) and
recorded the rest as not done: "the scheduler, webhook, retry, continuation
and crash-recovery failure paths still store nothing". A scheduled run that
failed was exactly as unreadable as before.

## Why the rest were different

Each of those paths fails its row with a statement that records the error and
nothing else (`fail_workflow_execution_unless_terminal` and its siblings,
`fail_resuming_…`, `fail_execution`, the chain runner's upsert), each with
its own guard: a dispatcher may not touch a `resuming` row, the resume
kernel may, the chain upsert must win a race with its own INSERT. Swapping
those for the engine's output-carrying finalizer would have changed which
rows each may fail.

## Decided

* **Fail first, attach after.** The path's own failure statement runs
  unchanged. Then a second, additive write stores the outputs:
  `attach_failed_run_outputs`, on both repositories (a path uses the one it
  completes its runs with), over two statements in
  `talos-execution-finalizer`.
  * Guard: the row is `failed` AND holds no output. It changes no status, no
    timestamp and no error, records no outcome, and can never replace an
    output or touch a row another writer finalized.
  * Sealed as that repository seals a completed run's output: encrypted
    under the workflow's org DEK when the repository holds the secrets
    manager (the returned format is bound), redacted plaintext otherwise.
  * Two steps, not one transaction. If the second is lost (a crash between
    them), the run is still recorded as failed with its error, which is the
    part that must not be lost. The outputs are for debugging.
* **One helper for the paths**:
  `talos_execution_result_collector::keep_failed_run_outputs(engine, id,
  attach)`. It takes the engine's partial results, calls the path's write
  only when a node completed, and logs (never propagates) a write that fails.
* **Wired**: the scheduler's run-failure arm; the webhook router's
  synchronous path, both its run-failure and its timeout arm; the
  continuation trigger; the resume kernel (crash recovery and the resume of
  a paused run, where the kept outputs include the checkpoint's seed); the
  chain runner; the GraphQL test run; the MCP enqueue path.
* **Retry stores the trigger again.** A retry resets the row's output when it
  starts. Its failure arm stored nothing, so a twice-failed run had lost its
  trigger input and a second retry ran on `{}`. It now stores what every
  other failed run stores: the trigger input and the completed outputs.

## A correction to the earlier record

It said its database test drove "the real finalizer (redaction, the size
bound, encryption at rest)". The test harness's repositories do not hold the
secrets manager, so that test drove the redacted-PLAINTEXT branch. The test
added here builds repositories the way the production paths do and drives
both branches, through both repositories.

## Mutations (a write to a terminal row, and a stored payload)

| Mutation | Caught by |
|---|---|
| the sealed attach drops `status = 'failed'` | database test ("outputs were attached to a running row") |
| the sealed attach drops "holds no output" | database test (an output was replaced) |
| the plaintext attach drops `status = 'failed'` | database test |
| a failed retry stores `None` | pin test |

Each restored and touched; all pass.

## Tests

* `controller/tests/failed_run_node_outputs_tests.rs` (+1), real rows, four
  ways (each repository, sealing and plaintext): the outputs land on a failed
  row that holds none, sealed at rest when the repository seals, with status
  and error unchanged; they read back; a second attach is refused and the
  first output stands; a running, completed, cancelled or waiting row is not
  written to.
* `talos-execution-result-collector/tests/keep_failed_run_outputs.rs` (2), a
  real engine run that fails: the path's write is handed the completed
  outputs, keyed by label, once; a completed run calls it never; a write that
  fails, or a row that does not take the outputs, is not an error.
* `talos-execution-orchestration`: a pin on retry's failure arm.

Not driven end to end: each wired path failing a real run (they need NATS, or
a scheduler tick, or a webhook). The engine hand-over, the helper and the
guarded write are each driven; each call site is the same five lines.

## Still store nothing (stated in the tool's description)

* A run in which no node completed.
* A run cut off from OUTSIDE the engine: the scheduler's own timeout wraps
  the function that owns the engine, so by the time it fires the engine is
  gone. (The engine's own workflow timeout is kept: that is the `Drop`.)
* An engine that could not be built (no graph, no module): nothing ran.
* The webhook router's ASYNCHRONOUS path was not touched. Its spawned task
  only logs a failed run; where that run's terminal status is written was
  not traced here, so nothing was attached to it.

## Stated limits

* The scheduler and enqueue paths key a COMPLETED run's output by node id;
  a failed run's is keyed by label on every path. `get_node_output` resolves
  both, so a reader sees no difference.
* Four crates gained a dependency on the result collector (scheduler,
  webhooks, the GraphQL crate, `talos-engine`). The collector depends on
  none of them.
