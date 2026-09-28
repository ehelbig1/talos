# 2026-09-28 — time queued for local inference is not charged to the job (RFC 0014 P2a)

**Why.** A worker serializes local (Ollama) LLM calls through a gate, cap 1. When
several workflows start together, a call can queue behind other runs' inference,
and every deadline the job had counted that queue time as its own work:
- the worker's outer job timeout;
- the inner timeout around `call_async`;
- the epoch callback's wall-clock bound;
- the controller's attempt window.

A job could fail because other workflows existed.

**Measured.** From the gate's histogram (`wasm_llm_queue_wait_ms`) over 30 days
(~3 071 local calls):
- 94 % waited under 10 ms;
- about 56 waited over 30 s and 9 over 60 s;
- none reached the 120 s queue-wait cap.

Every wait over 20 s fell inside a scheduled herd (the 06:00, 07:00 and 08:00
starts), 2–6 per morning.

**Decided.**
- **Deadlines measure work; waiting has its own bound.**
  `talos_workflow_engine_core::inference_wait` is the one home for the rule:
  `WaitAccounting`, a pure `begin`/`end`/`excluded` over given instants, plus
  `LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS` = 300. Worker and controller both use
  it, so the two clocks apply one rule and one cap.
- **Worker.**
  - The gate records a wait only when a call QUEUES: `try_acquire_owned` first,
    so a free slot records nothing.
  - The wait goes on the job's `InferenceWaitLedger`, a new trailing parameter
    of `execute_job_with_full_features`.
  - The three wall-clock bounds stand still while a wait is open:
    `with_pausable_deadline` for the outer and inner timeouts, and
    `wall_clock_expired` in the epoch callback.
  - The epoch callback reads the ledger only once the fixed deadline has passed,
    so its hot path stays lock-free.
  - The epoch TICK budget is untouched: ticks burn only while the guest runs.
- **Wire.** A new signed `JobProgress` (`waiting` / `admitted`).
  - It is signed like `JobResult` (worker Ed25519 or fleet HMAC) and
    domain-tagged `progress:`, so it can never verify as a result or the reverse.
  - It is published to `<reply_inbox>.progress`, derived from the SIGNED
    `reply_topic`.
  - Both `verify_dispatch` (primary) and `verify_no_replay_dispatch` exist up
    front, per the verify-once rule.
- **No request field, so no rollout order.** A controller that predates this
  change doesn't subscribe to the progress subject and the broker drops the
  messages; a new controller that hears none behaves exactly as before.
  - A signed request flag was rejected. It would bind a new segment into every
    dispatch, so during a rollout every old worker would refuse every dispatch
    from a new controller.
- **Controller.** `talos-workflow-engine-nats::attempt_wait::await_attempt`
  replaces the attempt's `tokio::time::timeout`.
  - `JobTransport::request_with_reply_inbox_and_progress` is a new method with a
    default that delegates, so a transport that doesn't override it behaves as
    before. The NATS transport subscribes to the reply inbox and the progress
    subject before publishing.
  - A report pauses the window only if it:
    - parses;
    - names this job and this attempt (the attempt is read lazily off the sent
      payload);
    - passes signature and replay verification;
    - comes from the first worker that reported for this attempt.

    Identity is checked before the signature, so a stray report never records a
    nonce. Everything else is ignored, and the window runs as before.
  - The window never passes the run deadline less `BUDGET_RESERVE_SECS`.
  - An unclosed wait is capped at 300 s.
- **Clock.** Every instant is `tokio::time::Instant::now().into_std()`: the same
  clock as `std` in production, and the one tokio's paused test clock moves. The
  gate's wait metric moved to it too.

**Deliberately NOT done:**
- Pausing the run's own budget (P2b).
- Fair or model-aware ordering (P2c).
- Pipeline jobs, which are dormant by config and report nothing.
- A metric: `talos-workflow-engine-nats` has no `talos-metrics` edge, and DX's
  refusal of that edge stands. The dispatcher logs
  `attempt_paused_for_local_inference` / `attempt_resumed_after_local_inference`
  at INFO; the worker logs each report.

**What a forger gets, stated.** A holder of the fleet key who has seen a job's
reply inbox can make the controller wait longer for that attempt, by at most
300 s. It cannot change a result, skip a gate or extend the worker's own
deadlines.

**Proof.**
- Unit tests:
  - `WaitAccounting`: 7.
  - `JobProgress`: 10 — domain separation both ways, tamper on every field,
    replay, wrong key, Ed25519, HMAC refused under Ed25519-only, wire shape.
  - Ledger and pausable deadline: 5, on the paused clock. The control is that
    the same job without a ledger times out.
  - Epoch wall-clock bound: 1.
  - Gate reporting: 3 — a free slot records nothing, a queued call records
    exactly its wait, an expired wait is excluded and closed.
  - Dispatcher: 13 — the admission rules, plus whole attempts through the
    transport seam. A job queued 90 s with 20 s of work in a 30 s window is
    accepted; the control is abandoned at 30 s. Work past the window, an
    unclosed wait (capped), a forged report and the run limit are all bounded.
- Production path: two concurrent completions on a cap of 1 record exactly one
  wait on the queued job's ledger, at BOTH call sites (`complete`,
  `complete_with_tools`).
- The worker binary's wiring is pinned textually by `inference_wait_pin.rs`: the
  pausable outer deadline, the ledger handed to the runtime, and the notifier
  aimed at the signed inbox.
- Mutations: 11 applied, 11 caught.

  | Mutation | Caught by |
  |---|---|
  | ledger dropped at `complete` | production-path test for `complete` |
  | ledger dropped at `complete_with_tools` | production-path test for tools |
  | dispatcher skips report verification | 3 dispatcher tests |
  | dispatcher skips the job-id check | dispatcher admission test |
  | dispatcher skips the attempt check | dispatcher admission test |
  | dispatcher skips the worker pin | dispatcher admission test |
  | window may pass the run limit | 2 dispatcher tests |
  | cap removed from `WaitAccounting` | 2 unit tests |
  | `state` not bound into the signature | tamper test |
  | ledger not passed in `main.rs` | the pin |
  | notifier aimed at a fixed subject | the pin |

  One `main.rs` mutation did not compile and was redone as a valid mutation.
- Suites: 1961/1961 across core, protocol, engine-nats, engine, worker-runtime,
  worker and replay. The workspace check (all targets) passes, and clippy
  `-D warnings` is clean on the touched crates.

**Stated limits.**
- No test drives a real worker, NATS and dispatcher together. The live check
  after deploy is the next herd: `attempt_paused_for_local_inference` in the
  controller log beside the worker's "reported local-inference wait" line, and no
  attempt timeouts on jobs that queued.
- A lost `waiting` message means the controller abandons the attempt as before
  P2; a lost `admitted` holds the window open for at most the cap.
- The per-worker gate means the fleet ceiling is still `replicas × cap` (P3).
