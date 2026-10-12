# 2026-10-12 — a Google Cloud push channel can start a workflow

**Why.** The third Google push integration was the last whose channels could
only run a module. Google Calendar got the workflow binding in
`2026-10-12-gcal-watch-starts-workflow.md` and Gmail's was put on the same
route in `2026-10-12-gmail-watch-starts-workflow.md`; this is the same shape
for Cloud Monitoring incidents.

**Observed.** Unlike Gmail, this integration had no workflow binding of any
kind: `GcpWatchRow` named a module only, and the inventory's `workflow_id:
None` was true.

**Decided.**
- **The channel row names the workflow** (`GcpWatchRow.workflow_id`,
  `skip_serializing_if` none: a row with no binding keeps the exact bytes it
  had). Independent of `module_id`, as on a calendar channel: with both
  bound, both run. (Gmail starts the workflow INSTEAD of the module; that
  predates all of this.)
- **Nothing replaces this row** — the user owns the Pub/Sub subscription, so
  there is no renewal. The one path that rewrites the row is the stamp a
  verified push leaves (`record_push_received`), which re-encodes the row it
  decoded. A test holds the binding across a stamp and the stamp across a
  bind.
- **One bind function**, `watch::bind_channel_workflow`, in the words and
  with the three refusals Calendar and Gmail use. The workflow is asked of
  `WorkflowRepository::get_workflow`; one field changes under the row lock.
  A create binds no workflow.
- **The push starts it through `ExecutionOrchestrationService::trigger`**, as
  the user whose row the push token names, in
  `dispatch::start_bound_workflow`, before the module dispatch.
- **The trigger carries identifiers only**: `{gcp_push: {integration_id,
  channel_id, incident_id, state, project_id, condition_name, message_id}}`,
  each of the last five present only when it is short and made of the
  characters Google's ids and resource paths use. No policy name, summary,
  documentation, metric value or resource label. `condition_name` is the
  condition's resource path, which names the alert policy; the workflow can
  read that with its own grants.
- **STATED LIMIT: Google offers no read of an incident by id.** The
  incident's own text (summary, documentation, labels) exists only in the
  push. A workflow that needs it binds a module on the same channel, which is
  handed the whole incident as before. Putting the text in the trigger was
  not done: a trigger input is stored in the clear with its execution, and
  the rule is one rule for every push integration.
- **One delivery of an incident state starts the workflow.** Pub/Sub delivers
  at least once; the start claims `gcp:workflow-started:{channel}:{incident or
  message id}:{state}` in Redis first (24 h), a key of its own so the
  module's claim on the same transition does not stop the workflow or the
  reverse. With no Redis, or when it does not answer, the workflow is started
  anyway, as on the module path.
- **A workflow-bound channel consults the execution pause**
  (`gcp_push_starts_work` takes the workflow too), with or without a module
  dispatch context: a start refused by the pause after the push was
  acknowledged is a dropped incident, where a 503 is a redelivery.
- **A refused start is recorded, not retried**: one WARN under `talos_audit`
  and one `workflow_not_started` row in the channel audit log with a reason
  from `OrchestrationError::push_refusal_reason`. Never the push token.
- **Binding surfaces.** `PUT /api/gcp/watch-channels/{id}/workflow` (session
  auth), `set_push_channel_workflow` with integration `google_cloud`, and
  `workflow_id` on the REST list and in `list_push_channels`.
- **`PubsubHandlerState` carries the trigger service and the Redis client
  itself**, not through the module dispatch context: that context exists only
  when NATS and the worker key do, and a workflow start needs neither.

**Deliberately NOT done.**
- **No frontend control** for the binding.
- **`workflow_not_started` does not feed `recent_failure`** on the channel
  list (that enrichment reads the module dispatch's failure rows). The audit
  log and the WARN are the record.
- **No metric**, for the reason given in the calendar record.

**Tests.**
- `controller/tests/gcp_watch_workflow_binding_tests` (4): bound only by its
  owner to the owner's own channel, and a refusal changes nothing; the push
  stamp keeps the binding and a bind keeps the stamp; a push on a bound
  channel is refused with `workflow_not_live` when the workflow is off,
  creates an execution for the channel's user whose `started_by` is
  `{push_channel, google_cloud, <channel>}` when it is on, says
  `trigger_service_not_wired` with no service and `workflow_not_found` once
  the workflow is another user's, and neither the incident's text nor the
  push token reaches the audit log; the inventory tells and sets the binding
  by integration name under the same rules.
- Unit: the stored row's bytes with and without a binding (and that a debug
  print shows the binding and not the token); the trigger input, with a
  realistic incident and with fields that are not identifiers; the claim's
  key; the pause predicate; the refusal's words.
- Mutations, each applied and reverted, each caught: the bind does not ask
  whose workflow (2 tests fail); the inventory hides the binding (3); the
  push stamp drops the binding; a refused start writes no audit row; the
  pause predicate ignores a workflow; the trigger carries the summary (2).

**Not verified, stated.** A real Pub/Sub push has not been received on this
change. The harness has no dispatch bus and its test workflow has an empty
graph, so a start is driven as far as the execution row and
`BoundWorkflowStart::Started` is not reached by a test. The harness has no
Redis: the claim (`AlreadyStarted`) is covered by its key's unit test and by
the function it shares with the module path, not by a run. The handler's
call into `start_bound_workflow` sits in a spawned task behind JWT
verification and is not driven end to end.

**One home.** `watch::bind_channel_workflow` for the binding;
`dispatch::start_bound_workflow` for the start;
`dispatch::gcp_push_trigger_input` for what a workflow is started with.
