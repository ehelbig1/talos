# An execution says what started it (2026-10-12)

`list_executions` returned nothing about how a run came to exist. A run
started by a schedule, by `test_workflow` and by an action link tapped on a
phone were rows that differed only in their timestamps.

## Found

* `workflow_executions` has no `trigger_type` column (the CHECK constraint
  the brief remembered is on `module_executions`). The run-level value lives
  in `provenance->>'trigger_type'`, and a structural lint forbids a column of
  that name beside the table.
* Of eleven statements that insert an execution row, three always wrote
  provenance: the scheduler, the webhook router and actor handoff.
  `trigger_workflow` wrote it only when an explicit `actor_id` was passed.
  `test_workflow_draft`, `call_workflow`, `bulk_trigger_workflow`,
  `trigger_workflow_as_actors`, `enqueue_workflow`, continuations, action
  links and push channels wrote none.
* Every reader then takes `COALESCE(provenance->>'trigger_type', 'manual')`,
  so a run started by a calendar push read as started by a person.
* `list_executions` selected neither provenance nor `is_test_execution`.
  `is_dry_run` does not exist; a stored dry run is told apart by its
  `__dry_run__` record (`2026-10-12-dry-run-says-what-it-stubbed.md`).

## Decided

* **A separate record, `provenance.started_by`:** `{kind, id?,
  integration?}`. One home, `talos_workflow_repository::origin`:
  `ExecutionOrigin` for the paths that record it, `started_by(…)` to read
  any row.
* **`provenance.trigger_type` is not touched.** A path that had no
  provenance now writes ONLY `started_by`. The self-monitor's alert scope,
  the operator digest's autonomous set and the schedule statistics filter on
  `trigger_type`, and each sees every row exactly as it did. A database test
  pins that.
* **`TriggerInput.origin` is a required field**, so the compiler named the
  six callers of the trigger service: MCP `trigger_workflow` (`manual`),
  GraphQL (`api`), action links (`action_link` with the link row's id, never
  the token), the memory evaluation (`evaluation`), and the two push
  receivers, Google Calendar and Jira (`push_channel` with the channel or
  registration id and its integration). The Jira receiver landed on main
  while this was being written; the required field is what found it.
* **The four MCP tools that insert a row themselves pass their origin**
  (`test_draft`, `call_workflow`, `bulk_trigger`, `trigger_as_actors`), and
  the two inserts that had no provenance column stamp their own
  (`enqueue`, `continuation`): each has one caller.
* **The paths that already mark their rows are READ from those marks**, not
  rewritten: `trigger_type` scheduled / webhook / actor_dispatch /
  actor_handoff with its id, `is_test_execution`, `replayed_from_id`,
  `triggered_by_module_execution_id`.
* **A row that records nothing is `not_recorded`, never `manual`.** "A
  person started this" is a claim; a silent row does not make it. Rows
  written before this change are in that state unless one of the marks
  above explains them.
* **`list_executions` and `list_recent_executions` return `started_by` and
  `is_test`.**

## Deliberately NOT done

* **New `trigger_type` values.** `VALID_TRIGGER_TYPES` is pinned against the
  self-monitor's unattended list by a cross-crate test, so a new value
  forces the question "does a failure of this alert?". That is the right
  question and it is the owner's: see below.
* **Rewriting the scheduler's, webhook router's or handoff's provenance.**
* **A column.** `provenance` is where this lives, and a migration to lift
  one key into a column is not needed to answer the question.
* **Backfilling old rows.**

## A decision this surfaces

A run started by a push channel or an action link is unattended, and its
`trigger_type` is absent, which the self-monitor reads as `manual`: **its
failure raises no alert.** That was true before this change and is true
after it. The origin is now recorded, so the choice can be made: alert on a
failed run whose `started_by.kind` is `push_channel`, `action_link`,
`continuation` or `enqueue`, or leave them out.

## Tests

* `controller/tests/execution_started_by_tests.rs` (migrated clone): each
  start path through the production function that inserts its row, read back
  through `list_executions`' query — action link, test, push channel,
  trigger with an explicit actor, api, call_workflow, bulk_trigger,
  trigger_as_actors, evaluation, test_draft, enqueue, continuation; then the
  schedule, the webhook, a replay through its own insert, a chain-shaped
  row, and a bare row (`not_recorded`). And: recording an origin adds no
  `trigger_type`.
* `origin` unit tests: round trip for every origin; stamping keeps what was
  there; the legacy marks; `not_recorded`; a bound on values something else
  wrote; and an inventory of the eleven insert statements with how each
  row's origin is known, which fails when one is added or removed.

## Stated limits

* The chain path's two failed-row upserts (a chain that never started) read
  `not_recorded`.
* A sub-workflow child writes no execution row (RFC 0012), so it has no
  origin to show; `sub_workflow_runs` is its record.
* The handlers are not driven end to end. What is driven is every insert
  function and the listing query.
* `get_execution_status` and the trace do not show `started_by`; the trace
  already prints the raw provenance.
