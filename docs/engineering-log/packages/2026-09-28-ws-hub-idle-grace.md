# 2026-09-28 — the shared WebSocket closes after a grace, not at once

**Why.** The operator's console showed `WebSocket connection to
'ws://localhost:3002/ws' failed: WebSocket is closed before the connection is
established` (`wsHub.ts:143`). That line is the hub's idle close: the moment the
last subscription left, it closed the socket, even one still CONNECTING. Any
unsubscribe followed at once by a resubscribe did that:
- in dev, React StrictMode mounts every effect twice (subscribe → unsubscribe →
  subscribe) on each page load;
- in production, any navigation between two pages that both subscribe does the
  same.

**Measured.** The operator's session on 2026-09-28 counted
`talos_ws_handshakes_total{outcome="authenticated"} = 4` and
`{outcome="closed_before_init"} = 2`, with 1 session active. That is two wasted
handshakes, one per page load, all from the idle close. Cosmetic in the
console, but real server work: each one is an upgrade and a handshake that the
server logs and counts.

**Decided.**
- `IDLE_CLOSE_GRACE_MS = 5_000`: when the last subscription leaves, the idle
  close is SCHEDULED, and any new subscription cancels it. The same socket, in
  whatever state it is in, carries the new subscription (started now if acked,
  replayed on ack otherwise). It is the standard graphql-ws client's
  `lazyCloseTimeout` shape. 5 s covers a route transition on a slow page. The
  cost is an idle socket held 5 s longer after a user leaves the last
  subscribing page.
- One timer, `idleTimer`, separate from the reconnect timer: the idle close
  still clears a pending reconnect, and `closeIdle` clears the idle timer, so
  the two cannot fire into each other. A timer that fires while subscriptions
  exist again does nothing.

**Deliberately NOT done.** A configurable grace (one constant, with no second
consumer), and any server change (the server already counts
`closed_before_init` at DEBUG, check 69's rule).

**Proof.** `wsHub.test.ts`, 13/13; full vitest 403 passed (1 skipped); eslint,
prettier and `tsc` clean.
- New: a subscription that unmounts and remounts while the socket is still
  CONNECTING keeps that socket (0 closes, 1 instance, 1 `start` after the ack).
- New: an idle socket is still open at `IDLE_CLOSE_GRACE_MS - 1` and closed,
  once, at the boundary.
- Updated: the two existing idle-close tests now advance past the grace.
- Run against `main`'s hub (with only the constant added so the file compiles),
  the StrictMode, boundary and first idle tests fail; with the fix they pass.

**Stated limit.** No browser drives the real server here. The live check after
deploy: reload the dashboard and expect `closed_before_init` not to move.
