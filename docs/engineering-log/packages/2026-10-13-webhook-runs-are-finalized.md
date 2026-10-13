# A webhook-started workflow run is recorded (2026-10-13)

The open item was small: "the webhook router's asynchronous path was not
touched; where its run's terminal status is written was not traced". Traced,
it is not written anywhere, and the synchronous mode's success is not
recorded either.

## What was found (read in the code, then reproduced on real rows)

* The router creates its execution row `queued`
  (`InitialExecutionStatus::Queued`). Nothing in the router moved it to
  `running`. No statement anywhere else does it for a webhook run: of the
  four `SET status = 'running'` statements, three belong to retry, the MCP
  enqueue path and the continuation trigger, and the fourth
  (`WorkflowRepository::mark_execution_running_from_queued`) had no caller.
  The router is now its caller.
* The success finalizers take only a `running` or `resuming` row.
  Reproduced: `mark_execution_completed` on a `queued` row returns `Ok` and
  leaves it `queued`.
* So, for a workflow bound to a webhook:

  | Mode | Run succeeded | Run failed |
  |---|---|---|
  | synchronous (`auto_respond: true`) | the caller got the output; the row stayed `queued` | recorded `failed` |
  | asynchronous (the default) | nothing written; the row stayed `queued` | logged only; the row stayed `queued` |

* A `queued` row counts toward a workflow's `max_concurrent_executions`, so a
  capped workflow would in time refuse its own webhook.
* Two comments said otherwise. The router's said the row stays `queued`
  "before the engine writes its terminal status", and `talos-engine`'s fence
  module concluded from the same premise that the path needed no fence. The
  engine writes no execution status. Both are corrected.

**Latent on the reference stack:** 0 executions in status `queued` on the
day (`list_recent_executions`). The push integrations start their workflows
through `ExecutionOrchestrationService::trigger`, not this path.

## Decided

* **The router claims its row before the run.**
  `mark_execution_running_from_queued`, before either mode. `Ok(false)`
  (the row was cancelled or finalized before dispatch) is not run: 409 with
  `{"status": "not_started"}`, and the dedup claim is KEPT, since the
  delivery arrived and its run was stopped on purpose. A claim that errors
  fails the row, releases the dedup claim and answers 500, like the other
  pre-dispatch failures.
* **The asynchronous mode records its run**
  (`talos_webhooks::record_async_run`): completed or waiting with its output,
  redacted and stored through the encryption-aware repository as the
  synchronous mode stores it; failed with its redacted error and the outputs
  of the nodes that completed.
* **A cancelled or superseded run is not a failure.** An operator's cancel
  and a fence abort leave the row alone (`classify_async_run`, pure).
* **The asynchronous run is fenced**
  (`fence::run_with_trigger_input_fenced_at_row_epoch`). Its row is `running`
  for the whole run now, like a scheduled run's, so crash recovery can
  reclaim it and the controller that started it must stop dispatching when
  that happens. The synchronous mode stays unfenced for the reason already
  recorded: it is bounded at 120 s, under the stale window, and a reclaim
  would abort a run its caller is waiting on.
* **One output projection for both modes** (`workflow_run::run_output`),
  where there was an inline loop.
* **The 202 body still says `"status": "queued"`.** It is what callers were
  told the acceptance looks like. The row's own status is now `running`.

## The decision this carries (why the PR is a draft)

Claiming the row as `running` makes an asynchronous webhook run
**crash-recoverable**: a controller restart mid-run is resumed from its
checkpoint, or from the start if it has none (at least once, as for a
triggered or scheduled run). The comment this change replaces called that "a
separate deliberate change". It is one, and it is the operator's.

1. **This change**: claim, fence, record. A webhook run behaves like every
   other run.
2. **Record without making it recoverable**: no way was found. A run cannot
   be recorded as completed while its row is `queued` without loosening the
   finalizers' status guard, and a row that says `queued` while its run is
   in flight can be "cancelled" by `cancel_queued_executions` without the
   run stopping.
3. **Leave it**: a successful webhook run is never recorded.

Recommendation: 1.

## Mutations

| Mutation | Caught by |
|---|---|
| a superseded (fenced) run is marked failed | unit test and database test |
| an operator-cancelled run is marked failed | unit test and database test |
| the stored output is not redacted | database test, once it drove a SEALING repository |
| the stored error is not redacted | database test |
| the router no longer claims its row | the pin test |

The third survived at first. The test used a repository with no secrets
manager, whose plaintext branch redacts by itself, so a recorder that forgot
to was hidden. The sealing branch stores exactly what it is handed.

## Tests

* `controller/tests/webhook_run_finalization_tests.rs` (2), real rows:
  * the defect at the statement (a `queued` row is not completed; a claimed
    one is; a cancelled row is not claimable);
  * `record_async_run` over a real engine run, through a sealing repository:
    a finished run is `completed` with its output sealed and redacted; a
    failed run is `failed` with a redacted error and the completed node's
    output; a cancelled or fenced run leaves a `running` row untouched.
* `talos-webhooks` `workflow_run` (2): the classification; a pin that the
  router claims before either mode, fences and records the asynchronous run,
  and runs the engine nowhere else.

Not driven end to end: a webhook delivery through the router into NATS.

## Stated limits

* The asynchronous task is a bare `tokio::spawn`, as it was. It is not
  bounded by a concurrency permit; the orchestration service's is private to
  that crate.
* No failure alert or execution event is published for a failed webhook
  run. The synchronous mode publishes none either. Not added here.
* The webhook REPLAY path forces the asynchronous mode and so goes through
  the same code.

## Rule added to CLAUDE.md

In "Engine retry & wire-format rules": a row created `queued` is claimed
before its run.
