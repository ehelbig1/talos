# 2026-09-29 — the controller's "queued for the gate" line said so on every call

**Found live** (the RFC 0014 live checks, 2026-09-29). The controller logged
`controller local LLM call queued for the gate` on 9 of 9 local LLM calls, with
`waited_ms` of 0 to 8. The fleet queue's own histogram
(`talos_local_llm_fleet_queue_ahead`) recorded all 9 as admitted with 0 ahead.
So the line claimed queueing that never happened.

**Cause.** The line fired whenever the measured wait was non-zero. Since P3b
that duration also counts the fleet queue's Redis round trip, so it is non-zero
on every call routed through the queue. The misleading-report class: a log line
an operator would read as "the controller is contending for the backend."

**Decided.**
- **"Queued" is read from the gate's observer, not from the duration.** The gate
  calls `QueueWaitObserver::begin_wait` only when a call actually waits, at
  either stage. The controller now passes a `QueuedFlag` observer and logs INFO
  only when it fired.
- **The decision is one pure function**, `gate_log(slot, queued)`:
  - wait expired → the existing WARN;
  - queued → INFO;
  - otherwise → nothing.
- `waited_ms` stays on both lines as the measured duration.

**Proof.**
- `the_queued_line_follows_a_real_wait_not_a_nonzero_duration` drives the real
  gate with its own semaphore: a free slot logs nothing, a held slot's second
  caller logs `Queued`, and a wait past the cap logs `WaitExpired`.
- The premise is pinned against a real Redis (`a_free_fleet_reports_nothing`):
  a call admitted at once through the fleet queue reports no wait to the
  observer, yet its measured wait is non-zero.
- The call-site pin now names the observer.

**Stated limit.** The worker has no equivalent line: its gate outcome goes to
`wasm_llm_gate_total` and `wasm_llm_queue_wait_ms`, and the latter also counts
the Redis round trip. A histogram of time spent is the right reading of that
duration; a "did it queue" log line was not.
