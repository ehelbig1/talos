# 2026-10-12 — a Google Calendar watch channel can start a workflow

**Why.** The owner wants a phone notification, with Accept and Decline, within
seconds of an invitation arriving. Talos already received calendar pushes and
synced what changed, but a push could only run one MODULE. The buttons are
minted by a workflow step (`action_links`) and delivered by another, so a push
had no route to them. No controller subscriber exists for the worker's
`agent-orchestration` subjects (`talos.agent.<target>.invoke`), so a
module-bound dispatch could not start a workflow either.

**Decided.**
- **The channel row names the workflow** (`WatchChannelRow.workflow_id`,
  `skip_serializing_if` none: a row with no binding keeps the exact bytes it
  had). Independent of `module_id`; a channel may have either, both or neither.
- **A renewal carries it.** `create_fresh_watch_channel_locked` takes the
  workflow as a REQUIRED argument, so the path that replaces the row cannot
  forget it. A binding that vanished at the first weekly renewal would fail
  nothing and start nothing.
- **One bind function**, `watch::bind_channel_workflow(pool, user, channel,
  Option<workflow>)`: the workflow is asked of `WorkflowRepository::get_workflow`
  (the read the trigger uses), then one field-scoped, row-locked update. It
  does not touch `updated_at_ms`, which the inventory reports as the channel's
  last EVENT. "No such workflow" and "not yours" are one answer to the caller.
- **The push starts it through `ExecutionOrchestrationService::trigger`**, as
  the user the channel's signed token attested to: the execution pause,
  ownership, liveness, the actor's budget and ceilings, the input schema and
  the concurrency limit all apply. Ownership is therefore checked twice, at
  bind and at every push; a row that names a workflow no longer the user's
  starts nothing (`workflow_not_found`).
- **The trigger carries event IDS only**: `{calendar_push: {integration_id,
  channel_id, calendar_id, changed, event_ids (≤ 50, plain ids only),
  truncated}}`. No title, time, guest or description. A trigger input is
  stored with its execution; the workflow reads the calendar with its own
  grants. This is also what lets the same workflow run from a schedule as a
  catch-up.
- **A workflow-bound channel consults the execution pause**
  (`gcal_webhook_starts_work` takes the workflow too). Without it a paused
  deployment would answer Google 200, advance the sync token and have the
  trigger refuse: the change dropped where a 503 defers it.
- **A start that is refused is recorded, not retried.** The sync token has
  already moved. One WARN under `talos_audit` and one row in
  `google_calendar_audit_log` (`workflow_not_started`) with a reason from a
  closed set (`workflow_not_found`, `workflow_not_live`, `execution_paused`,
  `authorization_denied`, `concurrency_limit`, `input_refused`,
  `trigger_failed`, `trigger_service_not_wired`). The error text itself goes
  to the server log only. Successful starts write no audit row: they are
  executions, and one row per calendar change would swamp the log.
- **Binding surfaces.** REST `PUT /api/google-calendar/watch-channels/{id}/workflow`
  (session auth) and the MCP tool `set_push_channel_workflow`, through a new
  default-refusing method on `PushChannelInventory` so the handler stays thin
  and holds no integration handle. `PushChannelRow.workflow_id` makes the
  binding visible in `list_push_channels`.
- **`sync_channel_events` uses `watch_api_client()`** like create and renew,
  so a test can stand in for Google. Unset, it is the same client as before.

**Deliberately NOT done.**
- **Gmail and Google Cloud channels.** Their inventories keep the default
  (`NotSupported`). Each has its own dispatch path; the same change there is a
  package of its own.
- **No periodic re-sync.** A push that arrives while the host is down is lost
  and the next change catches up. The workflow gets a schedule instead.
- **No frontend control.** The channel table does not offer a workflow yet.
- **No metric.** The audit row and the WARN are the record; a counter needs a
  seeded closed label set and an alert to be worth registering (check 58).

**Tests.**
- `controller/tests/gcal_watch_workflow_binding_tests` (4): a workflow is
  bound only by its owner to the owner's own channel and a refusal changes
  nothing; a renewal and a second create keep the binding; a push on a bound
  channel is refused with `workflow_not_live` when the workflow is off,
  creates an execution for the channel's user when it is on, says
  `trigger_service_not_wired` with no service, and is refused with
  `workflow_not_found` once the workflow is another user's; the inventory set
  binds by integration name under the same rules.
- Unit: the stored row's bytes with and without a binding; the trigger input
  (ids only, plain ids only, 50 at most); the closed set of reasons; the pause
  predicate; a source pin that the renewal passes the binding on.
- Mutations, each applied and reverted, each caught: bind without the
  ownership check; renewal drops the binding (caught by the DB test and by the
  source pin); the push never starts the workflow; the pause predicate ignores
  a workflow; the trigger carries a title.

**Not verified, stated.** A real Google push has not been received on this
change. The harness has no dispatch bus, so a start is driven as far as the
execution row and no further. `handlers::pubsub_tests::
valid_jwt_but_unreadable_lookup_defers_for_redelivery` in `talos-google-cloud`
failed 2 runs in 3 under plain `cargo test` and passes with
`--test-threads=1`: it asserts a process-global counter that a sibling test
also moves. It is not touched here (this change adds one field to a struct
literal in that crate) and is not fixed here.

**One home.** `watch::bind_channel_workflow` for the binding;
`handlers::calendar_push_trigger_input` for what a workflow is started with.
