# A calendar-watch renewal that arrives mid-rotation is handed the replacement (2026-10-08)

## What was failing

`a_renewal_that_waited_does_not_act_on_the_row_it_read_before_waiting`
(`controller/tests/gcal_watch_fleet_lock_tests.rs`) failed on `main` in three
of the four runs after `sqlx` 0.9 merged (#1189) — including on a commit that
changed only documentation — and on a pull request that changed only `base64`.
In the hundred or so runs before that it had failed once.

Run 30 times locally: **29 failures on `main`; 7 on the commit before
`sqlx` 0.9.** It was never a reliable test; the bump made it an unreliable
one that almost always failed.

## Why

A renewal replaces a channel in this order: stop the old one at Google,
delete its row, ask Google for a new one, write the new row. Most of that
time is Google's call, and for all of it there is no row.

`renew_watch_channel` read the row it was asked to renew BEFORE taking any
lock, because the lock it takes is keyed by the calendar and only the row
knows the calendar. So a second renewal of the same channel that started
during the first one's rotation read nothing and returned "not found" for a
channel that had in fact just been renewed.

Traced on the failing test: the first renewal read its row at 1 ms and had
deleted it by 8 ms. The second read at 22–35 ms. It was late because the
pool had one idle connection at that instant (two more were still being
handed back by the call before), so it opened a new one.

**What changed with `sqlx` 0.9 is which of the two was slow, not how slow
anything is.** On 0.8 the first renewal usually stalled about 25 ms between
its read and its lock, which happened to give the second time to read. On
0.9 it does not stall. Measured directly, 0.8.6 beside 0.9.0: a new
connection takes 3.2 ms and 2.6 ms (release build); a released connection is
idle again in 0.2 ms in both. Nothing got slower; a coincidence the test
relied on went away. Why the first renewal no longer stalls was not
established.

In production this is two controller replicas whose renewal loops reach the
same channel within the same second or so: one renews it, the other logs a
failure for a channel that is fine.

## Changed

* **A renewal takes a lock keyed by `(user, channel uuid)` before it reads.**
  The same two-level lock as the create lock (process-local mutex, then a
  Postgres advisory lock), under a separate key, taken first; the create lock
  is still taken after the read, as before. The order is always renewal lock
  then create lock, and the create path takes only the second.
* **The replacement row records the row it replaced** (`renewed_from`). A
  renewal that finds its row gone looks for a row that says it replaced it,
  and returns that. A uuid that was never a channel is still "not found".
* The field is absent from rows that replaced nothing and from every row
  already stored, so those are written byte for byte as before.
* The order of the rotation itself is unchanged (delete before create —
  `docs/integration-pattern.md` records why).

## Pinned

* `a_renewal_that_starts_while_another_is_mid_rotation_is_handed_the_replacement`:
  starts the second renewal, from the other replica, once Google has received
  the first one's request — so the row is certainly gone (asserted) — and
  requires the same replacement, one Google channel, one stop, one row; then
  that a caller with the old uuid later still gets the replacement without
  Google being asked anything. It fails with the renewal lock removed and
  fails with the replacement lookup disabled.
* A unit test holds the stored row's format: an old row reads back and is
  rewritten unchanged; a renewed row round-trips its `renewed_from`.
* The test that was failing: 30 of 30 with the change. The whole binary, six
  tests: 10 of 10.

## Stated

* A renewal now holds two lock transactions, so two pooled connections, for
  its duration. Renewals run one at a time per replica.
* `renewed_from` links one generation. A caller holding a uuid two renewals
  old is told "not found".
* **Gmail's renewal has the same shape** — it reads the row and then locks —
  and was not changed here. It is recorded in `docs/integration-pattern.md`.
* The `sqlx` 0.9 pull request's own CI run passed, and so did the run its
  commit got on `main`; of the nine runs after those, five passed. A test
  that passes one time in thirty locally is not caught by one green run.
