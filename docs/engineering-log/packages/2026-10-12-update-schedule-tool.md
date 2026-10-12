# `update_schedule`: a schedule's time can be changed in place (2026-10-12)

MCP had `create_schedule`, `delete_schedule`, `pause_schedule` and
`resume_schedule`. Moving a schedule by ten minutes was delete-then-create:
a window with no schedule, and a "permanently delete" call for an edit.
`create_schedule`'s own refusal told the caller to "update the
cron_expression via the scheduler UI".

## Decided

* **`update_schedule(schedule_id, cron_expression?, timezone?)`.** At least
  one of the two; the one left out keeps its stored value. `cron` is accepted
  as an alias, as in `create_schedule`.
* **`ScheduleRepository::update_timing`, one transaction.** The row is read
  `FOR UPDATE` scoped to its owner, merged, the next fire time computed for
  the merged pair, and written. A scheduler tick cannot claim the row between
  the read and the write.
* **The next fire time is recomputed from now, for a paused schedule too.**
  `resume_schedule` does not touch `next_trigger_at`, so a paused schedule
  edited without this would fire at its old time on resume.
* **A pair with no next fire time writes nothing** (`NoNextTrigger`). A
  schedule stored with a NULL `next_trigger_at` is one the due-claim query
  never selects: saved, and never run.
* **`is_enabled` and `last_triggered_at` are not touched.** Pausing and
  resuming stay `pause_schedule` / `resume_schedule`; a call that names
  neither field is refused and says so.
* **One validator for both tools.** `validate_schedule_cron` (field count,
  parse, the 60-second minimum interval) and `validate_schedule_timezone`
  were lifted out of `create_schedule`, which now calls them.
* **Not found and not yours are one reply**, as for pause, resume and delete.

## GraphQL

Already has `updateSchedule`, keyed by `workflow_id`, org-aware, which also
sets `is_enabled`. It was not changed. The two differ in key and in scope
(the MCP tools are per user, by `schedule_id`), as the existing MCP and
GraphQL schedule tools already do.

## Tests

* `controller/tests/schedule_update_tests.rs` (migrated clone): another
  user's schedule is neither changed nor acknowledged, and a schedule that
  does not exist reads the same way; the owner moves the time and the next
  fire follows, with history untouched; only the timezone changes the stored
  UTC time; a paused schedule stays paused and gets its new time; a pair with
  no next fire time writes nothing.
* `schedule_change_tests`: either field alone or both; nothing to change is
  refused; a given value passes the checks `create_schedule` applies.

**Mutations** (the owner predicate is a tenancy guard):

| mutation | result |
|---|---|
| the `FOR UPDATE` read no longer scoped to the caller | caught: `another_users_schedule_is_neither_changed_nor_acknowledged` |
| neither statement scoped to the caller | caught by the same test |
| only the `UPDATE`'s predicate removed | not observable: the scoped read returns no row first. It is kept as a second statement of ownership. |

## Stated limits

* The handler is not driven end to end (it needs an `McpState`); its parsing
  and the repository method are.
* A schedule whose new time has already passed today fires tomorrow. There
  is no "run now".
