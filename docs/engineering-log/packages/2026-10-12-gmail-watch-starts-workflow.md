# 2026-10-12 — a Gmail watch starts its workflow through the trigger service

**Why.** The owner's busiest push source is Gmail and his Gmail workflows
poll. The request was to give Gmail the workflow binding Google Calendar got
earlier the same day (`2026-10-12-gcal-watch-starts-workflow.md`), because
`set_push_channel_workflow` answered "channels of this integration cannot
start a workflow".

**Observed, and it was not what the request said.** A Gmail watch row has
named a workflow since the push integration was written (`GmailWatchRow.
workflow_id`), and a push on such a row did start it. Four things were wrong
with how:

- **The inventory said otherwise.** `GmailPushChannelInventory` reported
  `workflow_id: None` for every watch, under a comment that this integration
  "starts a module, never a workflow". So `list_push_channels` showed a bound
  watch as starting nothing and `set_push_channel_workflow` refused.
- **Only a create could set it, and nothing asked whose workflow it was.**
  `create_watch` copied the caller's `workflow_id` into the row unread. The
  push asked (`WHERE id = $1 AND user_id = $2`), so this was a watch that
  could never start anything rather than one that started another user's
  workflow.
- **Re-pointing the module cleared it.** The settings page re-points a
  watch's module by creating it again and sends no workflow; the existing
  row's `workflow_id` was overwritten with `None`.
- **The start went through `trigger_continuation_workflow`**, the route that
  resumes a run after an approval or a suspension. It refuses an archived
  workflow and nothing else about its lifecycle: a workflow the owner had
  switched OFF was started by a push. It does not apply the workflow's input
  schema or its concurrency limit either. A refusal was one log line.

**Decided.**
- **The push starts the workflow through `ExecutionOrchestrationService::
  trigger`**, as the watch's own user, in `dispatch::start_bound_workflow`:
  ownership, liveness, the execution pause, the actor's budget and ceilings,
  the input schema and the concurrency limit all apply. `talos-gmail` no
  longer depends on `talos-continuation-trigger`.
- **The trigger carries message ids only**: `{gmail_push: {integration_id,
  channel_id, email_address, changed, message_ids (≤ 50, alphanumeric only),
  truncated}}`. The mailbox address is the counterpart of the calendar id: it
  says which account to read. The function that builds it is given ids and
  nothing else, so no sender, subject or label can reach it. The ids are the
  ones no earlier delivery of the same push claimed (the existing Redis
  claim), or every id on the page when Redis did not answer.
- **THE TRIGGER INPUT CHANGED SHAPE.** It was `{gmail_channel_id, payload:
  {source, email_address, history_id}, triggered_by: "gmail_push"}`. A
  workflow that read those keys must read `gmail_push` instead. The private
  workflows repository was searched for all three old keys and reads none.
- **A refused start is recorded, not retried**, as for a calendar: one WARN
  under `talos_audit` and one `workflow_not_started` row in the channel audit
  log with a reason from `OrchestrationError::push_refusal_reason`. The
  history cursor advances either way.
- **One bind function**, `watch::bind_channel_workflow`, and one ownership
  question, `workflow_is_bindable` (the read the trigger uses), asked by the
  bind and by a create that names a workflow. "No such workflow" and "not
  yours" are one answer. The bind changes one field under the row lock and
  leaves `updated_at_ms` (the inventory's "last event") alone.
- **A create that names no workflow leaves the binding alone.** Clearing is
  `bind_channel_workflow(.., None)`. This changes what `POST
  /api/gmail/watch-channels` with no `workflow_id` does to an existing bound
  watch: it used to clear the binding and now does not.
- **Binding surfaces.** `PUT /api/gmail/watch-channels/{id}/workflow`
  (session auth) and `set_push_channel_workflow` with integration `gmail`,
  through the inventory. `list_push_channels` shows the binding.
- **The continuation trigger lost its push variant** (`TriggerSourceKind::
  GmailPush`) and the memory injection only that variant did. The trigger
  service injects an actor-bound workflow's curated memory by the same rule
  (`inject_memory: false` opts out), so a pushed run is grounded as before.
  Two dependencies of that crate went with it.

**Not changed, stated.**
- **On a Gmail watch the workflow is started INSTEAD of the module** when
  both are bound (`select_dispatch_target`); on a calendar channel both run.
  That difference predates this change and is now written in the tool
  descriptions.
- **`workflow_id` is written as `null` when unset** (no `skip_serializing_if`):
  every stored row already has the key, so removing it would change bytes.
- **The Redis claim is one round trip per message.** It is the module path's
  and is bounded by the history page.
- **Google Cloud channels** keep the default refusal; a package of its own.
- **No frontend control** for the binding yet.

**Tests.**
- `controller/tests/gmail_watch_workflow_binding_tests` (5): bound only by
  its owner to the owner's own watch, and a refusal changes nothing; a create
  binds only the caller's own workflow, refuses before Google is asked and
  leaves no row; a renewal and a create that names no workflow keep the
  binding; a push on a bound watch is refused with `workflow_not_live` when
  the workflow is off, creates an execution for the watch's user whose
  `started_by` is `{push_channel, gmail, <channel>}` when it is on, says
  `trigger_service_not_wired` with no service and `workflow_not_found` once
  the workflow is another user's; the inventory tells and sets the binding by
  integration name under the same rules.
- Unit: the trigger input (the mailbox and ids only, alphanumeric ids only,
  50 at most, `truncated` on both sides of the cap); the refusal's words; a
  source pin that the renewal passes the binding on.
- Mutations, each applied and reverted, each caught: the inventory hides the
  binding (4 tests fail); a create does not ask whose workflow; a create with
  no workflow clears the binding; the bind does not ask whose workflow (2
  fail); a renewal drops the binding; a refused start writes no audit row.

**Not verified, stated.** A real Pub/Sub push has not been received on this
change. The harness's test workflow has an empty graph and there is no
dispatch bus, so a start is driven as far as the execution row (created for
the watch's user, with its origin) and the trigger then reports the graph as
unloadable; `BoundWorkflowStart::Started` is not reached by a test.
`dispatch_to_workflow` (collect, claim, call) needs a NATS client to build
its context and is not driven; `start_bound_workflow`, which it calls, is.

**One home.** `watch::bind_channel_workflow` and `workflow_is_bindable` for
the binding; `dispatch::start_bound_workflow` for the start;
`dispatch::gmail_push_trigger_input` for what a workflow is started with.
