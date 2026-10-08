# Gmail watch: one registration across replicas, one renewal at a time (2026-10-08)

The same race #1195 fixed for Google Calendar, which the integration guide
recorded as open for Gmail — and, found on the way, a lock that was never
shared between replicas.

## Reproduced first

`controller/tests/gmail_watch_fleet_lock_tests.rs`, two `GmailWatchService`s
on two pools of one database and an in-process stand-in for Google. On the
code before this change, three of four failed:

| test | before |
|---|---|
| two replicas create one mailbox's watch at once | Google asked to register the mailbox twice |
| two renewals of one watch on one replica | the second: "gmail watch … not found" |
| a renewal arriving, on the other replica, while one is mid-rotation | answered before the rotation finished |
| 32 renewals of uuids that are not watches, 8 connections | passed (it guards the fix) |

Two defects:

* **The create lock was process-local.** Gmail's `create_locks` was the
  in-process mutex alone; Calendar's became a fleet lock (process mutex plus
  a Postgres advisory lock) earlier. Two replicas could both register.
* **The renewal read once, before any lock, and acted on that read.** A
  second renewal waited for the first and then stopped the mailbox's
  subscription again (`users.stop` ends every subscription of the mailbox),
  deleted a row already gone and registered again — or, arriving mid-rotation,
  found nothing.

## Changed

* The create lock is taken through `acquire_fleet`
  (`gmail:<user>:<integration>`), for create and for renew. Since #1199 such a
  lock also outlives the pool's 60-second idle-transaction limit.
* A renewal looks for its row unlocked; a uuid that is not there gets the
  replacement it names, or waits for any renewal in flight and lets that
  lock go before looking again — so it never holds one pooled connection
  while waiting for another.
* A row that exists: a per-watch renewal lock (`gmail-renew:<user>:<uuid>`,
  always before the create lock), a re-read, the create lock, a re-read, then
  the rotation as before (stop, delete, create, keep the history cursor).
* The replacement row records the row it replaced (`renewed_from`; absent
  from rows that replaced nothing and from every row already stored).
* `create_fresh_watch_locked` takes the create guard by reference, as
  Calendar's does, so creating without the lock does not compile.
* `renew_watch` is public (the integration test calls it, as Calendar's
  test calls its equivalent); `require_by_id`, left unused, is gone.
* A test-only hook points the service's Google client at another origin.

## Pinned

The four tests above pass, the binary 30 of 30 runs. Each was shown to fail
on a deliberate breakage of the change: no wait on a missing row, a
replacement lookup that never matches, replicas not sharing the create lock,
the renewal lock held while looking again (30-second pool timeout), and no
re-read after the renewal lock. A unit test holds the stored row's format.

## Stated

* Run only against an in-process stand-in for Google and a local test
  database.
* A renewal of a real watch holds two lock transactions and uses a third
  connection for its reads.
* A renewal handed another's replacement returns success, so the second
  replica's loop records a renewal too.
* `renewed_from` links one generation.
