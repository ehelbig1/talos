# The engine records what was sent (2026-10-16)

The question "how many of the assistant's messages are acted on" could not be
answered. A tap is recorded (`workflow_action_tokens.used_at`, 91 in the
fourteen days before this package), but a send was not: the only trace of a
message having left is the `notify-*` adapter's output, which is encrypted at
rest, so a count of sends was a count of send nodes that completed, and a
completed send node on a quiet day sends nothing.

## Decided

- **The engine records a send from the adapter's verdict, at node
  completion.** `docs/notification-contract.md` already fixed what every
  adapter returns (`provider`, `sent`, `parts_total`, `parts_sent`, the action
  counts). `ControllerNodeHook::on_node_completed` reads it with
  `talos_workflow_engine_core::delivery_verdict::read_delivery_verdict` and
  writes one `message_deliveries` row per send that happened. Nothing in a
  module changes; the catalog contract test now also reads every adapter's
  real verdict through the engine's reader, so the two cannot drift apart.
- **A row is identifiers and counts.** Workflow, execution, node, the provider
  word, five counts, the run's start kind, a timestamp. No recipient, no
  service address, no text. `talos_admin_read` may read it.
- **A dry run writes nothing, by the engine's own flag first.**
  `NodeCompletionContext` gained `dry_run` (the engine's
  `workflow_executions.dry_run`, carried into child runs); the hook refuses on
  it before it reads the output, then on the worker's `__dry_run__` stamp, then
  on the adapter's own `dry_run` and `skipped` words. A verdict that says a
  message left on a dry run is a stub's verdict.
- **A rehearsal is recorded and left out of the report.** The row keeps
  `started_by_kind`; `message_engagement` reads `IS DISTINCT FROM 'test'`. A
  test send reaches a real phone and is still not a message the owner was
  meant to act on.
- **A tap is set against the execution that minted its link.**
  `workflow_action_tokens.source_execution_id` joins `message_deliveries.execution_id`,
  under both the workflow's and the token's `user_id`. The report
  (`get_message_engagement`, `AnalyticsRepository::message_engagement`) gives,
  per workflow: sends, parts, actions, one-tap actions, executions, executions
  with at least one tap, taps. `executions_tapped / executions` is the
  engagement rate.
- **A malformed verdict is counted, not written.** The reader refuses a
  verdict outside the contract's bounds (`Malformed(field)`) and the hook
  counts it (`talos_message_delivery_record_failures_total{reason="malformed"}`);
  the table's CHECKs are a backstop, not the reason. A failed insert is logged
  and counted (`reason="db"`), never returned: an under-counting report is the
  consequence, not a failed node.
- **Its own retention clock.** `reap_execution_side_tables` deletes rows older
  than `MESSAGE_DELIVERY_RETENTION_DAYS` (365), as the cost rollup has its own
  window: a year of sends and taps is the engagement history, and the rows are
  small.
- **Tenancy as `judge_scores`.** No row-level policy: the writer is the engine
  on the pool, the one reader joins `workflows` under the caller's user id. A
  tenant-scoped reader added later brings the policy with it (the 2026-10-15
  rule).

## Deliberately NOT done

- **Email sends are not recorded.** `send-html-email` is outside the
  notification contract (its output is `sent`, `message_id`, `thread_id`, no
  provider or parts). Recognising a second shape would be a second contract
  for one template; if email engagement is wanted, the email senders should
  return the notification verdict, and the reader needs no change.
  **Superseded the same day** by `2026-10-16-every-message-sender-returns-its-verdict.md`:
  the email sender returns the verdict, and the reader DID change (a tap rate
  over every send would have read a plain report as ignored).
- **No new reserved `__key__`.** The verdict is the contract's documented
  return, read where it is; an output protocol key would have asked every
  adapter to say the same thing twice.
- **Not a security control, not write-ceiling gated.** An adapter that lies
  about its counts inflates a report, as a module that emits `__ops_alert__`
  can raise an alert. The row is platform bookkeeping keyed by the workflow,
  like `judge_scores`, not an actor-data write.
- **The pipeline-step hook does not record.** `on_pipeline_step_completed`
  carries no execution or node id. The contract already says a message is sent
  by ONE send node, so a notify adapter inside a chained pipeline is not a
  shape the platform recommends.
- **No `UNIQUE (execution_id, node_id)`.** A `for_each_connection` node runs
  the same node once per connection in one execution, and each run's send is a
  send.

## Measured

- Fourteen days before this package: 91 action-link taps, almost all in the
  work-ticket flow; sends unmeasurable in SQL (encrypted outputs).
- `message_deliveries` row: three uuids, five integers, two short strings, one
  timestamp. At the current fleet's rate (a few dozen sends a day) a year is
  under 20k rows.

## Latent vs live

Live: every `notify-ntfy` and `notify-home-assistant` send on the fleet is
recorded from the first run after deploy. Nothing is backfilled; history
starts at the deploy.

## Stated limits

- A report's first useful window is after the deploy.
- A tap on a link that reached the phone by email (the morning email's
  buttons) is counted as a tap only if the minting execution also sent a
  notification; otherwise its send is not in this table (see email above).
- The hook's insert is `tokio::spawn`ed; a controller stopped between the
  node's completion and the insert loses that one row.

## One home

- The reader: `talos_workflow_engine_core::delivery_verdict`.
- The write: `talos_execution_repository::message_deliveries::record_message_delivery`,
  called only from `ControllerNodeHook::record_message_delivery_if_present`.
- The report: `AnalyticsRepository::message_engagement`, served by the MCP
  tool `get_message_engagement`.
- The retention: `talos_advanced_repository::MESSAGE_DELIVERY_RETENTION_DAYS`.
- Rule recorded in CLAUDE.md (the notification-contract bullet).
