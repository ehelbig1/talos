# 2026-09-28 — one local-inference queue across processes (RFC 0014 P3b)

**Why.** After P3a the controller and each worker gated their local LLM calls,
but each with its own semaphore, so the single-slot Ollama still saw one request
per process. P3a's measurement (30 days): 108 worker requests arrived while a
controller call held the backend, ~14 s each, and that wait was charged to the
worker call.

**Decided.**
- **A counting semaphore in Redis, keyed per backend**, in
  `talos_local_inference::fleet`:
  - holders scored by lease expiry;
  - waiters scored by an `INCR` ticket, so the queue is FIFO across processes;
  - each waiter's liveness expiry, refreshed on every poll.
- **One Lua script does every transition** (`acquire` / `renew` / `release`) on
  Redis's own clock (`TIME`), so no two hosts' clocks are ever compared. The
  four keys share a hash tag and expire when idle. The key id is the SHA-256 of
  the normalised backend URL, so credentials in a URL never reach a key.
- **Taken after the process gate** (`gate::admit`), under one wait budget:
  - a process has at most `cap` callers in the fleet queue; the rest queue
    locally with no Redis round trip;
  - a wait at either stage is reported ONCE to the observer, so a worker's job
    deadlines stand still for a fleet wait (P2a);
  - `TALOS_LOCAL_LLM_MAX_IN_FLIGHT` is the backend's slot count, applied
    fleet-wide too. One knob.
- **It never refuses:**
  - every Redis call is bounded at 2 s; an error or a slow call proceeds on the
    process gate, logged once per outage (WARN on entry, INFO on recovery);
  - a fleet wait past the cap proceeds ungated and releases the process permit,
    as an expired process wait does;
  - leases live 30 s, renewed every 10 s. A holder that dies frees its slot
    within 30 s; a waiter that gives up leaves at once (a drop guard); a waiter
    that dies leaves within 5 s;
  - a lease that cannot be renewed in time is counted `lease_lost` and the call
    goes on.
- **No fencing token.** Ollama cannot check one, and over-admission is harmless
  (the backend queues it, as before). The token only stops a holder renewing a
  lease it lost.
- **Installed at boot** in both processes, beside their other Redis users:
  `worker::local_llm_fleet::install` and `bootstrap::local_llm_fleet::install`.
  Nothing is installed with no `REDIS_URL`, a cap of 0,
  `TALOS_LOCAL_LLM_FLEET_ADMISSION=false` (new, default `true`, `both`), or a
  Redis unreachable at boot.
- **Series**, closed set `leased | wait_expired | unavailable | lease_lost`, all
  pre-seeded:
  - controller: `talos_local_llm_fleet_admission_total`. The outcomes are
    duplicated into `talos_metrics::LocalLlmFleetOutcome` so `talos-metrics`
    does not pull in redis/reqwest; an exhaustive match maps them, and a test
    pins the labels equal;
  - worker: `wasm_llm_fleet_admission_total`, from the global meter, because the
    queue is installed before any runtime exists.
  - **No alert**: none of the outcomes is a refusal, and there is no baseline.

**Deliberately NOT done, stated.**
- **Two URLs for one backend make two queues**, each falling back to P3a's bound
  against the other. Dev and the chart give both processes the same `OLLAMA_URL`.
- **A Redis restart loses the queue.** Calls in flight keep their process
  permits.
- **Processes configured with different caps** each apply their own to the
  shared queue.
- **Polling, not pub/sub.** A waiter polls every 200 ms. That is one script call
  per waiter per poll, and waits are measured in seconds.

**Proof.** `talos-local-inference/tests/fleet_redis.rs` (`// ci-store: redis`),
where each `FleetAdmission` has its own connection and its own process gate and
stands in for a process:
- two processes with cap 1 reach the backend one at a time, and every call
  records `leased`. The control (two process gates, no fleet) overlaps;
- cap 2 across three processes admits two, never three;
- FIFO: four waiters from four processes are admitted in queue order;
- a holder that dies (stops renewing, never releases) frees the slot after about
  one lease;
- a live holder keeps its slot past one lease, so a second caller's shorter wait
  expires (`wait_expired`);
- a waiter that gives up does not stand in the queue for its liveness window;
- a Redis connection frozen mid-call (through a freezable proxy, not
  `CLIENT PAUSE`, which stalled every test beside it) falls back to the process
  gate after one bounded call, recording `unavailable`;
- a fleet wait is reported once to the observer; a free fleet reports nothing.

Plus unit tests on the key id, the hash tag, the labels and the production
timing, and the controller's label pin.

**Mutations: 6 applied, 6 caught.**

| Mutation | Caught by |
|---|---|
| the fleet stage skipped | 7 tests |
| no lease renewal | the live-holder test |
| a waiter that gives up is not removed | the gave-up test |
| no bound on a Redis call | the stalled-Redis test |
| LIFO tickets | the FIFO test |
| expired leases not reaped | the dead-holder test |

**Suites:** 1 094 passed (1 pre-existing skip) across `talos-local-inference`
(with Redis), `talos-llm`, `talos-worker-runtime`, `worker` and `talos-metrics`.
The workspace check (all targets) and clippy `-D warnings` are clean. The
Redis tests ran against a throwaway container, not the stack's Redis.

**Stated limits.**
- No test drives the controller and a worker against the stack's Redis and a
  real Ollama. The live check after deploy:
  - both boot logs say "local LLM fleet admission: on";
  - both `outcome="leased"` series climb;
  - Ollama's request log shows no two `/api/chat` requests in flight at once,
    from any process.
