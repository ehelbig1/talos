# 2026-09-28 — time queued for local inference is not charged to the run (RFC 0014 P2b)

**Why.** P2a stopped a job's own deadlines counting time queued behind other
workflows' local inference. The RUN's budget still counted it, so a workflow
could still fail because other workflows existed — only later, at its
`execution_timeout_secs` instead of at a node's window. `pa-chief-of-staff`
(420 s budget) runs a sub-workflow whose LLM calls queue in the 08:00 herd.

**Decided.**
- **One clock per run.** `talos_workflow_engine_core::RunWaitClock` holds the
  UNION of the run's jobs' waits, keyed by job id and measured on the
  controller's clock.
  - While any job waits, the run is paused. Two parallel queued branches pause
    it once.
  - It is capped at `LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS` (300 s), the same as
    a job.
  - `begin` / `end` are idempotent, and an unknown job's `end` changes nothing.
  - A fresh clock is stamped per run beside the deadline, so a reused engine
    handle never inherits a previous run's credit.
- **Everything that bounds the run reads the LIVE deadline**, which is the
  stamped deadline plus the clock's excluded time:
  - `run_with_workflow_timeout`: the deadline is re-read each time it is
    reached;
  - the dispatcher's per-attempt clamp (`attempt_wait::live_run_deadline`, one
    home);
  - the attempt window's upper limit (`RunLimit`, re-read live);
  - `bounded_child`, the inline sub-workflow / judge / ensemble window
    (`pausable_child_wait`).
- **The dispatcher reports into the run's clock.**
  - `DispatchJob::run_waits` carries the run's clock, on both the single-node
    and loop-body dispatches.
  - A VERIFIED `waiting` / `admitted` (P2a's checks) also moves the run clock.
  - When the attempt ends, however it ends, the job's wait on the run is closed,
    so a lost `admitted` cannot hold the run open.
- **Sub-workflows.** `AdapterSet` carries the building run's clock as
  `parent_run_waits`, and a child run's clock forwards every `begin` / `end` to
  it. A job queued inside a sub-workflow therefore pauses the parent run's
  budget too. Forwarded waits cannot collide with the parent's own, because job
  ids are unique.
- **`DispatchJob::deadline` keeps its meaning: the STAMPED deadline.** The live
  value is read in exactly one place per consumer. A draft
  `DispatchJob::live_deadline` had no caller and was deleted rather than left
  as a second home.
- **Clock.** Every instant uses tokio's clock as `std`, as P2a did.

**Deliberately NOT done, stated.**
- **`bounded_child` pauses on the run's UNION**, so a sibling branch's queueing
  also holds an inline child's window. The child's own run clock cannot be
  reached from there. This errs toward more time, and is bounded by the run cap
  and by the run's own live deadline.
- **Pipeline jobs** (dormant by config) carry no clock.
- **Fair and model-aware admission** is P2c.

**Proof.**
- **Unit tests:**
  - `RunWaitClock` (4): overlap counted once, idempotence, parent forwarding,
    cap.
  - Dispatcher (5):
    - a verified wait reaches the run clock;
    - the attempt runs past the STAMPED run limit when the run itself paused;
    - an ended attempt closes its run wait;
    - a forged report moves nothing;
    - the per-attempt clamp reads the live deadline. Its control: the same
      stamped deadline with no clock is refused before the wire.
- **Engine unit tests:**
  - Run timeout (4): a queued job does not spend the budget; the control (no
    report) times out at 30 s; an unclosed wait is capped; every run gets a
    fresh clock.
  - Parent forwarding through `AdapterSet` (1).
  - Child window (4): through `pausable_child_wait` and through `bounded_child`
    itself; the control; waits from before the child started do not lengthen
    it.
- **End to end through the engine:**
  - `tests/run_budget_local_inference_wait.rs`: a 30 s budget with a node queued
    90 s then working 20 s completes. The control, with the wait unreported,
    times out at 30 s.
  - `loop_body_gates`: loop-body and single-node jobs carry the SAME run clock.
- **Mutations: 10 applied.**
  - 9 caught by a failing test.
  - 1 caught as a HANG: the run timer ignoring the clock re-arms at a past
    instant and spins under the paused test clock. It was killed after an hour
    and would be a CI timeout, not a pass.
  - 1 more first SURVIVED: `bounded_child` reverting to the plain timeout. The
    helper tests could not see the call site. It is closed by the
    `bounded_child` test and re-run: caught.
- **Suites:** 2 075 / 2 075 across the touched crates. The workspace check (all
  targets) and clippy `-D warnings` are clean.

**Stated limits.**
- **No test drives a real controller, NATS and worker together.** The live check
  after deploy is a herd run whose job logs
  `attempt_paused_for_local_inference` and whose run finishes past its stamped
  budget. A run that still times out logs "workflow budget elapsed after
  excluding local-inference queueing" with the excluded milliseconds.
- **The run can outlive its budget by up to 300 s.** The stale sweep fails a
  `running` row 60 minutes after it started (`STALE_EXECUTION_MINUTES`). The
  largest budget on this fleet is 900 s, so budget + 300 s stays far below that;
  no workflow here has a budget over 3 300 s. A budget of 55 minutes or more
  could now cross the sweep's line. That is recorded, not guarded, because none
  exists.
