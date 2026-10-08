# A fleet lock is no longer let go after 60 idle seconds (2026-10-08)

Found by the review of #1195.

## The defect

`CreateLockMap::acquire_fleet` (`talos-integration-helpers`) takes a
Postgres advisory lock inside a transaction and holds the transaction open,
idle, until the guard drops. Every pooled controller connection sets
`idle_in_transaction_session_timeout = '60s'` (`talos-db`), which ends any
transaction left idle that long — and with it the lock.

So a holder slower than a minute lost its lock partway, and the next caller,
on this replica or another, went ahead beside it. The only user is the Google
Calendar watch path: the create lock (the result is a second Google channel,
which keeps pushing until it expires) and, since #1195, the renewal lock (the
result is the "not found" that change fixed). A renewal holds its locks
across up to two upstream calls of up to 30 seconds each, after up to 45
seconds of waiting for the create lock.

## Reproduced

`a_held_fleet_lock_outlives_the_pools_idle_transaction_limit`
(`controller/tests/gcal_watch_fleet_lock_tests.rs`): a pool whose connections
end idle transactions after one second (the production setting, scaled), a
lock held for two and a half, then a second replica asking for it. Before
the change it got the lock at once: "the lock was released while its holder
still held the guard".

## Changed

The lock transaction sets its own limit, `SET LOCAL
idle_in_transaction_session_timeout = '300s'` (`FLEET_LOCK_HOLD_LIMIT`), for
itself only — the pool's 60 seconds still applies to every other
transaction. A unit test pins the statement to the constant and the constant
above the longest legitimate hold (the create-lock wait plus two upstream
calls).

## Stated

* A holder that is stuck, not slow, now keeps the lock and its pooled
  connection for up to five minutes, where it was one. Waiters still give up
  after 45 seconds with an error, as before.
* One more round trip per lock taken.
