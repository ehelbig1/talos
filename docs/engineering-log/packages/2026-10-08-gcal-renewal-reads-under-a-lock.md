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

* **Renewals of one channel are serialized by a lock keyed by
  `(user, channel uuid)`** — what the caller holds, where the create lock is
  keyed by something only the row knows. The same two-level lock as the
  create lock (process-local mutex, then a Postgres advisory lock). The order
  is always renewal lock then create lock; the create path takes only the
  second.
* **The replacement row records the row it replaced** (`renewed_from`). A
  renewal that finds its row gone looks for the row that says it replaced
  it, and returns that. A uuid that was never a channel is still "not found".
* **The row is looked for before the renewal lock is taken, and again after.**
  The lock is a transaction on a pooled connection. A request for a uuid that
  is not a channel waits for any renewal of it in flight and then lets the
  lock go before it looks again, so it never holds one connection while
  waiting for another. (The first version of this change took the lock
  first. A review pointed out what that costs: 32 such requests against an
  8-connection pool held all of it for the 30-second acquire timeout —
  reproduced, and now a test.)
* The field is absent from rows that replaced nothing and from every row
  already stored, so those are written byte for byte as before.
* The order of the rotation itself is unchanged (delete before create —
  `docs/integration-pattern.md` records why).

## Pinned

* `a_renewal_that_starts_while_another_is_mid_rotation_is_handed_the_replacement`:
  the stand-in for Google holds its answer to the first renewal, so the test
  is mid-rotation for as long as it needs. It asserts the row is gone,
  starts the second renewal from the other replica, asserts that it is still
  waiting 300 ms later, lets Google answer, and requires the same
  replacement, one Google channel, one stop, one row; then that a caller
  with the old uuid later still gets the replacement without Google being
  asked anything. It fails if a missing row does not wait for the renewal in
  flight, and fails if the replacement lookup never matches.
* `renewing_ids_that_are_not_channels_does_not_hold_the_pool`: 32 at once
  against 8 connections all come back "not found". It fails (after the
  30-second acquire timeout) if the lock is held while looking again.
* A unit test holds the stored row's format: an old row reads back and is
  rewritten unchanged; a renewed row round-trips its `renewed_from`.
* The test that was failing, and the whole binary of seven: 30 of 30.

## Stated

* A renewal of a real channel now holds two lock transactions, and uses a
  third connection for its reads: three at its peak, where it was two. The
  renewal loop runs them one at a time per replica.
* **A lock held this way is lost after 60 seconds, and that is not new.**
  Every pooled connection sets `idle_in_transaction_session_timeout = '60s'`
  (`talos-db`), and a fleet lock is a transaction that sits idle. A rotation
  slower than that — two upstream calls of up to 30 seconds each — loses its
  locks partway. For the renewal lock that is the old behaviour back; for
  the create lock, which has always had this, it is a second Google channel.
  Found by the review, read in the configuration, not exercised, and not
  changed here: it belongs to `acquire_fleet` and every caller of it.
* A renewal that is handed another's replacement returns success, so the
  loop on the second replica records a renewal too: two audit rows for one
  renewal. The branch that already did this (gone when re-read under the
  create lock) did the same.
* A row the replacement lookup cannot decode is skipped with an error log,
  as the renewal listing does, rather than failing the lookup.
* The renewal-lock map gains an entry per uuid asked about until the hourly
  sweep drops the idle ones.
* `renewed_from` links one generation. A caller holding a uuid two renewals
  old is told "not found".
* **Gmail's renewal has the same shape** — it reads the row and then locks —
  and was not changed here. It is recorded in `docs/integration-pattern.md`.
* The `sqlx` 0.9 pull request's own CI run passed, and so did the run its
  commit got on `main`; of the nine runs after those, five passed. A test
  that passes one time in thirty locally is not caught by one green run.
