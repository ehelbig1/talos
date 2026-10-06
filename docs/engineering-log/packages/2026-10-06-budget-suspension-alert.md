# A budget that suspends an actor raises an alert (2026-10-06)

## Measured

On 2026-10-05 an actor reached its hourly execution cap under
`on_budget_exceeded = 'suspend'`. The pre-check suspended it, and every
workflow bound to it was refused for 1 h 45 min. Nothing announced it: a
suspension was the `actors.status` column and, on each refused start, a WARN
in the controller log. Package CD (2026-09-17) made `alert` raise an ops
alert; it recorded `suspend` as untested and raised nothing for it.

On the reference fleet at the time of writing (read-only):

| `actors.status` | policy | actors | with an hourly cap |
|---|---|---|---|
| active | `suspend` | 4 | 3 |
| active | `alert` | 2 | 2 |
| active | none | 1 | 0 |

So three actors could be suspended this way. `ops_alerts` held three budget
refusal alerts and no suspension alert, because none could be written.

## Changed

* The one place a budget suspends an actor —
  `budget_precheck::check_actor_hour_budget_for_batch` — raises an ops alert
  when its call is the one that suspended it: source `talos`, severity `high`,
  dedup key `talos/actor/<actor_id>/suspended` (one row per actor, outside the
  `…/budget/<cap>` refusal keys). The phone workflow already forwards source
  `talos`.
* Setting the actor back to `active` closes that alert
  (`resolved_source = 'signal'`). It is done where the status is written —
  `ActorRepository::update_actor_status` and `update_actor_status_scoped` — so
  the MCP tool and the GraphQL mutation both do it and a third surface cannot
  forget to.
* A second suspension of the same actor reopens the same row
  (`occurrence_count` 2, `reopened_at` set).

## Decided

* **Raised once, by the call that changed the row.** The pre-check used
  `suspend_actor`, whose guard is "not archived or terminated": its row count
  is 1 for an actor that is already suspended. The new
  `suspend_active_actor` matches `status = 'active'` and returns whether it
  matched. Starts that reach the cap together all read `active`; one suspends
  and alerts, the others do neither.
* **Not throttled.** A suspended actor is refused by its status before any
  budget is read, so the recorder is reached once per suspension.
* **A failed alert write never changes the gate.** The suspension and the
  refusal stand; the failure is a WARN
  (`event_kind = actor_suspension_alert_not_raised`). The same on resume
  (`actor_suspension_alert_not_resolved`): the alert stays open, which
  over-reports.
* **Inside a caller's transaction the close runs under a savepoint.** A
  statement that fails in a Postgres transaction aborts all of it; without
  the savepoint a failed alert update would have rolled back the resume.
  The close commits or rolls back with the status change.
* **The resolve statement has one home.**
  `talos_ops_alert_store::resolve_by_dedup_key` (any executor), which
  `OpsAlertRepository::resolve_by_dedup_key` now calls. It was inline in the
  repository, which the actor repository cannot depend on.

## Mutation testing

A budget gate decides whether an actor's work runs, so each guard was
mutated and `controller/tests/actor_budget_alert_tests.rs` run against it:

| Mutation | Caught by |
|---|---|
| the suspending call does not raise the alert | three tests |
| the suspend statement matches an already-suspended actor | `concurrent_starts_at_the_cap_raise_the_suspension_alert_once` |
| any status change closes the alert, not only a resume | `a_budget_suspension_raises_one_alert_and_a_resume_closes_it` |
| a resume (pool) does not close it | the same test |
| a resume (caller's transaction) does not close it | `a_resume_inside_a_transaction_closes_the_alert_with_the_commit` |
| the resolve statement ignores the user | `closing_a_suspension_alert_touches_only_the_named_users_row` |

The last one survived the first run: the resume is ownership-gated before the
resolve is reached, so no test drove the resolve statement's own `user_id`
predicate. The test named there was added for it. An alert's key is unique
per user only, so that predicate is what keeps one user's resume from closing
another's row.

## Not done

* **Changing the default policy.** `on_budget_exceeded` still defaults to
  `suspend` (the column default, the scaffold and `set_actor_budget`). The
  operator's decision of 2026-09-17 kept all three modes; with the alert a
  suspension is no longer silent, and stopping a runaway actor outright is a
  defensible default. Changing it is the operator's call.
* **An alert for the operator's own `suspend_actor`.** The person who did it
  knows. Resuming such an actor finds no alert to close and changes nothing.
* **Suspension on the other caps.** Only the hourly cap suspends; the total,
  fuel and token caps refuse. Unchanged.
* **A metric for suspensions.** The alert is the signal a person acts on;
  `talos_actor_budget_refusals_total{mode="suspend"}` already counts the
  refusal that caused it.

## Stated limits

* An actor suspended before this change has no alert, and resuming it closes
  nothing. None is suspended on the reference fleet now.
* The alert is written after the status change, not in one transaction with
  it: a controller that dies between the two leaves a suspended actor with no
  alert. The next refused start does not raise it (the status refuses first).
