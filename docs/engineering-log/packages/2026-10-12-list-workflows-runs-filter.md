# `list_workflows(runs: true)`, and two counts that no longer contradict (2026-10-12)

`list_workflows(status: "active")` returned 17 workflows while 27 had an
enabled schedule. `session_start.schedule_health` printed
`active_workflows: 17` beside `workflows_with_active_schedules: 27` under a
note that defined the second as "Active workflows that have ≥1 enabled
schedule", with a code comment "Always ≤ active_workflows".

## The class

The `workflows.status` versus `is_enabled` family
(`2026-09-05-workflow-liveness-and-child-run-ledger.md`). `status = 'active'`
means PUBLISHED. A draft with an enabled schedule is dispatched from its
draft graph, and four of the reference fleet's drafts already were on
2026-09-05. On 2026-10-12, 27 workflows had an enabled schedule and 17 were
`active`, so at least ten scheduled ones were drafts. The count had been loosened to
`status != 'archived'` on 2026-05-07 for exactly that reason, and the note
beside it was left saying "Active".

## Decided

* **`list_workflows(runs: true)`** lists the workflows the platform runs:
  DISPATCHABLE (`talos_workflow_liveness::dispatchable_sql`: not archived,
  not disabled) and with a way to start — an enabled schedule, an enabled
  webhook trigger, or a run in the last 7 days (`RUNS_RECENT_DAYS`). One
  home, `talos_workflow_repository::runs_sql`. It combines with `status`,
  `type` and `tag`, and the reply states what the filter meant.
* **Not called "live".** `talos_workflow_liveness::is_live` already means
  "published and not paused", which is the meaning that misled here.
* **The third arm is how a push-bound workflow is found.** A watch
  channel's workflow binding lives in integration state, which SQL cannot
  filter on; so does an action link's target. A workflow started only that
  way is listed if it ran in the last 7 days.
* **`session_start` reports both scheduled counts from one statement:**
  `workflows_with_active_schedules` (not archived; unchanged) and the new
  `active_workflows_with_active_schedules` (its `status = 'active'` part,
  which IS a subset of `active_workflows`). The notes say which is which and
  that the first can be larger.

## Deliberately NOT done

* **Changing what `status: "active"` returns**, or what `active_workflows`
  counts. Both mean "published", other readers depend on that, and the
  liveness record says not to collapse the two axes.
* **A migration or a new index.** Each `EXISTS` is served by an existing
  one: `workflow_schedules(workflow_id)` (unique),
  `webhook_triggers(workflow_id)`, `workflow_executions(workflow_id,
  started_at DESC)`.

## Stated limits

* A workflow started only by a push channel, an action link or another
  workflow, that has not run in 7 days, is not listed by `runs: true`.
* A sub-workflow child writes no `workflow_executions` row (RFC 0012), so a
  workflow that runs only as a child is not found by the third arm.
* `runs: true` says a workflow has a way to start, not that its last run
  succeeded.

## Tests

`controller/tests/list_workflows_runs_filter_tests.rs` (migrated clone):
ten workflows of one user, one per case — four that run (active scheduled,
draft scheduled, draft webhook, ran yesterday) and six that do not (idle,
ran a month ago, schedule paused, webhook disabled, archived with an enabled
schedule row, disabled) — plus another user's; the count uses the same
filter as the page; `status: "active"` both omits the drafts that run and
includes one that does not; the two filters combine. And: the two scheduled
counts reconcile, with the larger allowed to exceed `active_workflows`.
