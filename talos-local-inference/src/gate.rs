//! In-flight gate for LOCAL (Ollama) LLM exchanges.
//!
//! Moved here from `talos_worker_runtime::host::llm_gate` in RFC 0014 P3a so
//! the controller's `talos_llm::OllamaClient` takes the same gate: one rule,
//! one cap, one env var, in both processes. The worker keeps a thin wrapper
//! that records a queued call on the job's `InferenceWaitLedger` (P2a).
//!
//! ## The defect this closes
//!
//! `LOCAL_LLM_EXCHANGE_TIMEOUT_SECS` (60 s; replaced by progress deadlines in
//! RFC 0014 P1, see [`crate::stream`]) was documented on
//! the worker's `host::limits` as a bound on **one call**: *"a cold-start with a
//! 7B+ model can take 20–40 s while the model loads into VRAM. 60 s gives
//! headroom without masking an actually-stuck call."* That reasoning is
//! entirely about a single request's own service time, and until this module
//! existed nothing made it true. Talos issued an unbounded number of
//! simultaneous `/api/chat` requests to one backend, so the 60 s was not a
//! per-call budget — it was **shared across every request in flight**, and a
//! call could spend all of it waiting for somebody else's inference.
//!
//! Measured on the reference deployment over 31 days, all 1194 completed
//! LLM module executions, bucketed by how many other LLM module executions
//! overlapped them in wall-clock:
//!
//! | concurrent siblings | n | p50 | share over 60 s |
//! |---|---|---|---|
//! | 0 | 1029 | 8.5 s | 1.3 % |
//! | 1 | 99 | 37.8 s | 20 % |
//! | 2 | 45 | 83.3 s | 58 % |
//! | 3 | 14 | 1106 s | 86 % |
//!
//! One concurrent sibling quadruples p50 and takes the timeout rate from
//! 1.3 % to 20 %. That is a saturated single-server queueing curve, and the
//! important consequence is that **serializing is FASTER in aggregate, not
//! merely fairer**: two calls whose solo p50 is 8.5 s finish in ~17 s back to
//! back, against a measured p50 of 37.8 s when they run together. Concurrency
//! on a compute-saturated inference backend is pure overhead — it splits one
//! machine between two requests and adds scheduling on top.
//!
//! ## Shape, and why it cannot refuse
//!
//! The gate QUEUES. It never refuses, and it has no error variant. This is
//! deliberate and it follows the in-house precedent: every signed-RPC subject
//! bounds itself with `Semaphore::acquire_owned().await` (`MAX_IN_FLIGHT` 8 /
//! 16 / 32 — see `talos-rpc-subscribers`), and not one of them has a
//! `try_acquire`. A slow call that succeeds beats a fast call that is refused.
//!
//! The wait is bounded by [`LOCAL_LLM_QUEUE_WAIT_SECS`], and when that expires
//! the call **proceeds UNGATED** — i.e. it degrades to exactly the behaviour
//! that shipped before this module. That is what makes the gate a Pareto
//! change rather than a trade: the worst case it can produce is the old
//! behaviour plus a bounded wait, and there is no input for which it turns a
//! call that would have succeeded into one that is declined.
//!
//! ## What the gate is NOT
//!
//! * **Not a fleet-wide bound.** The semaphore is a process-global
//!   `OnceLock` inside one worker. `WORKER_REPLICAS` defaults to 2, so the
//!   effective ceiling against a shared backend is `replicas × cap`. Stated
//!   rather than implied: on a two-worker fleet a cap of 1 still permits two
//!   simultaneous exchanges.
//! * **Not, by itself, a bound ACROSS processes.** Since RFC 0014 P3a the
//!   controller's `talos_llm::OllamaClient` — memory consolidation, graph-RAG
//!   entity extraction, evaluation, the teacher audit — takes this gate too,
//!   but its OWN copy: the semaphore is process-global. Since P3b a call that
//!   gets its process permit then queues in [`crate::fleet`], shared by every
//!   process calling the backend; when that queue is not installed or Redis
//!   does not answer, this gate is the whole bound again.
//! * **Not applied to external providers.** Anthropic / OpenAI / Gemini serve
//!   requests in parallel and bill per token; serializing them would be a
//!   straight latency regression for no benefit. The gate keys on exactly the
//!   `is_local` flag the call sites already compute to choose the HTTP client.
//! * **Not a bound on streaming.** `llm_streaming.rs` holds a long-lived SSE
//!   connection whose whole point is to stay open; a permit held for the life
//!   of a stream would deadlock the two gated paths behind it.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::fleet::{FleetAcquire, FleetAdmission, FleetLease};

/// Simultaneous LOCAL LLM exchanges permitted per process (worker or
/// controller).
///
/// **1**, and the number is measured rather than chosen for tidiness: the
/// Ollama that serves this deployment's inference logs
/// `OLLAMA_NUM_PARALLEL:1` at startup with nothing set in its environment —
/// one inference slot per loaded model. Stated as the observation it is: that
/// is the value Ollama 0.31.2 RESOLVED on that host, and this module did not
/// measure WHY it resolved to 1 rather than 4, so no claim is made about what
/// a different host would pick. (The bundled `docker-compose.yml` Ollama sets
/// no `OLLAMA_NUM_PARALLEL` either, and its 0.5.1 build logs the unset
/// sentinel `0` rather than a resolved value, so its effective parallelism was
/// not observable the same way.)
///
/// **The honest limit: Talos cannot see the backend's parallelism.** An
/// operator running a GPU host that genuinely serves four requests at once
/// should raise this to match, via [`MAX_IN_FLIGHT_ENV`]; leaving it at 1
/// there would serialize work the backend could have overlapped. The default
/// is set for the deployment shape Talos actually ships, and the knob exists
/// because that shape is not the only one.
pub const DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT: usize = 1;

/// Override for [`DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT`]. `0` disables the gate
/// entirely (every call proceeds immediately, pre-gate behaviour); an
/// unparseable or empty value falls back to the default rather than to 0,
/// because a typo must not silently switch a control off.
pub const MAX_IN_FLIGHT_ENV: &str = "TALOS_LOCAL_LLM_MAX_IN_FLIGHT";

/// How long a call may wait for a permit before giving up on the queue and
/// proceeding ungated.
///
/// 120 s, and the derivation matters more than the value. The wait must be
/// long enough that a real queue drains rather than dissolving under load —
/// at the measured solo p50 of 8.5 s and p90 of 18 s, 120 s clears a backlog
/// of roughly six calls — and it must not be the binding constraint on how
/// long a job may take, because that is the job timeout's job
/// (`WASM_EXECUTION_TIMEOUT_SECS`, 120 s, applied in `worker/src/main.rs`
/// around the whole execution). Setting it equal to that ceiling makes the
/// intent explicit: the gate never decides a job's fate; if a job is going to
/// die of old age it dies at its own deadline, on the timeout that already
/// existed, with the message it already had.
///
/// Since RFC 0014 P2 the wait itself is no longer charged to the job timeout
/// (it is recorded on the job's `InferenceWaitLedger`), so this constant is now
/// the bound on ONE call's queueing, and `LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS`
/// (300 s) bounds a job's queueing in total.
pub const LOCAL_LLM_QUEUE_WAIT_SECS: u64 = 120;

/// Why a call is running without a permit.
///
/// Kept as an enum rather than a bool so the two reasons cannot be conflated
/// in the metric: `Disabled` is a deployment that turned the control off and
/// is a permanent steady state, `WaitExpired` is a queue that did not drain
/// and is a real load signal. Collapsing them would put a configuration
/// choice and a saturation event in one series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ungated {
    /// `TALOS_LOCAL_LLM_MAX_IN_FLIGHT=0`.
    Disabled,
    /// The permit did not arrive within [`LOCAL_LLM_QUEUE_WAIT_SECS`].
    WaitExpired,
}

/// The outcome of asking for a local-LLM slot.
///
/// Dropping the value releases the permit, so a call site that acquires and
/// then discards the binding holds the slot for zero time and gates nothing —
/// which is precisely the quiet failure this module exists to prevent. There
/// is deliberately no `is_held()` accessor and no `Into<bool>`: nothing
/// downstream should branch on it, the permit's only job is to be alive for
/// the duration of the exchange.
///
/// **`#[must_use]` is defence in depth here and NOT the guard — measured, not
/// assumed.** Both production sites bind `Option<LocalLlmSlot>` (the external
/// branch has no slot to take), and `#[must_use]` on `T` does not propagate to
/// `Option<T>`; a probe that reduced the call site to a bare expression
/// statement produced no clippy diagnostic under `-D warnings`. And `let _ =`
/// silences the attribute by design at any type. So the attribute catches a
/// bare-statement discard of a NAKED `LocalLlmSlot` and nothing else. **The
/// actual guard is the three production-path cases at the tail of
/// `llm_failure_metrics_tests.rs`**, which read peak concurrency out of the
/// mock backend and were proved by mutation to fail on exactly this revert.
#[must_use = "the permit is released when this value is dropped; bind it for \
              the whole LLM exchange or the gate does nothing"]
#[derive(Debug)]
pub enum LocalLlmSlot {
    Held(Admitted),
    Ungated(Ungated),
}

/// What an admitted call holds for the whole exchange: its process's permit
/// and, when the fleet queue is installed and Redis answered, its fleet lease
/// (RFC 0014 P3b). Both are released on drop.
#[derive(Debug)]
pub struct Admitted {
    _local: OwnedSemaphorePermit,
    _fleet: Option<FleetLease>,
}

impl Admitted {
    /// Whether this call also holds a fleet lease — `false` when the fleet
    /// queue is not installed or Redis did not answer.
    pub fn holds_fleet_lease(&self) -> bool {
        self._fleet.is_some()
    }
}

/// Label for the worker's `RuntimeMetrics::record_llm_gate`. Closed,
/// compile-time set — never a caller-derived value.
impl LocalLlmSlot {
    pub fn outcome_label(&self) -> &'static str {
        match self {
            LocalLlmSlot::Held(_) => "acquired",
            LocalLlmSlot::Ungated(Ungated::Disabled) => "disabled",
            LocalLlmSlot::Ungated(Ungated::WaitExpired) => "wait_expired",
        }
    }
}

/// Every value `outcome_label` can produce, for metric pre-seeding.
///
/// Absent is not zero: `increase(...) > 0` over a series that has never been
/// touched matches nothing, so a gate that has correctly never fallen back
/// must render as an explicit 0 rather than as silence.
pub const GATE_OUTCOME_LABELS: [&str; 3] = ["acquired", "disabled", "wait_expired"];

/// Parse the cap from a raw env value. Pure, so the parsing rule is testable
/// without the process-global latch below.
///
/// A missing, empty or UNPARSEABLE value falls back to the default rather than
/// to 0. A typo must not silently switch a control off — that is the
/// fail-in-the-reassuring-direction shape this repo keeps finding.
pub fn resolve_max_in_flight(raw: Option<&str>) -> usize {
    raw.map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT)
}

/// Resolved cap. Read once — the semaphore below latches with it, so a
/// mid-process env change could not take effect anyway and pretending
/// otherwise would be worse than saying so.
pub fn max_in_flight() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| resolve_max_in_flight(std::env::var(MAX_IN_FLIGHT_ENV).ok().as_deref()))
}

/// The process's gate, or `None` when the cap is 0 (gate disabled).
pub fn process_gate() -> Option<&'static Arc<Semaphore>> {
    static SEM: OnceLock<Option<Arc<Semaphore>>> = OnceLock::new();
    SEM.get_or_init(|| match max_in_flight() {
        0 => None,
        n => Some(Arc::new(Semaphore::new(n))),
    })
    .as_ref()
}

/// Where a queued call reports its wait. The worker's `InferenceWaitLedger`
/// implements it (RFC 0014 P2a: the job's deadlines stand still while the
/// call queues); the controller has nothing to report to and passes `None`.
pub trait QueueWaitObserver {
    /// The call has started to queue.
    fn begin_wait(&self) -> impl std::future::Future<Output = ()> + Send;
    /// The call has stopped queueing (admitted, or gave up).
    fn end_wait(&self) -> impl std::future::Future<Output = ()> + Send;
}

/// The observer for a caller that has nobody to tell.
pub enum NoWaitObserver {}

impl QueueWaitObserver for NoWaitObserver {
    async fn begin_wait(&self) {
        match *self {}
    }
    async fn end_wait(&self) {
        match *self {}
    }
}

/// Take a slot on this process's gate — and, when [`crate::fleet::install`]
/// found Redis, on the fleet queue for the backend — waiting up to
/// [`LOCAL_LLM_QUEUE_WAIT_SECS`] across both.
///
/// Returns the slot and how long the wait took. **Call this BEFORE starting
/// the exchange's deadlines**: the entire point is that queue time is not
/// charged to a budget that is supposed to measure one call's own service
/// time.
///
/// When the call has to QUEUE at either stage, the wait is reported to `wait`
/// once. A slot that is free is taken without reporting.
pub async fn acquire_process_slot<W: QueueWaitObserver>(
    wait: Option<&W>,
) -> (LocalLlmSlot, Duration) {
    admit(
        process_gate(),
        crate::fleet::installed(),
        Duration::from_secs(LOCAL_LLM_QUEUE_WAIT_SECS),
        wait,
    )
    .await
}

/// The whole decision, with the semaphore, the fleet queue and the wait cap
/// supplied — for the same testability reason as [`acquire_from`].
///
/// 1. **The process's own gate first.** `try_acquire_owned` first: a tokio
///    semaphore hands a released permit to the longest waiter, so a free
///    permit means nobody is queued and taking it jumps no one. A process
///    therefore has at most `cap` callers in the fleet queue; its other calls
///    queue here, with no Redis round trip.
/// 2. **Then the fleet queue**, until the same deadline. Redis unavailable →
///    the call proceeds on its process permit (the P3a behaviour); the fleet
///    wait expired → the call proceeds ungated, releasing its process permit,
///    exactly as an expired process wait does.
pub async fn admit<W: QueueWaitObserver>(
    permits: Option<&Arc<Semaphore>>,
    fleet: Option<&FleetAdmission>,
    wait_cap: Duration,
    wait: Option<&W>,
) -> (LocalLlmSlot, Duration) {
    let Some(sem) = permits else {
        return (LocalLlmSlot::Ungated(Ungated::Disabled), Duration::ZERO);
    };
    // tokio's clock (the same clock as `std` in production) so the reported
    // wait and the job's `InferenceWaitLedger` measure the same interval.
    let started = tokio::time::Instant::now();
    let deadline = started + wait_cap;
    let reported = AtomicBool::new(false);
    let report = || async {
        if !reported.swap(true, Ordering::Relaxed) {
            if let Some(w) = wait {
                w.begin_wait().await;
            }
        }
    };
    let finish = |slot: LocalLlmSlot| async {
        if reported.load(Ordering::Relaxed) {
            if let Some(w) = wait {
                w.end_wait().await;
            }
        }
        (slot, started.elapsed())
    };

    let permit = match sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            report().await;
            match tokio::time::timeout_at(deadline, sem.clone().acquire_owned()).await {
                Ok(Ok(p)) => p,
                // `acquire_owned` errors only when the semaphore is CLOSED, and
                // nothing in this process ever closes it. Rendered as
                // `WaitExpired` rather than unwrapped, because a panic inside a
                // host function unwinds the whole job — and rather than as
                // `Disabled`, which would report a closed semaphore as an
                // operator's configuration choice.
                Ok(Err(_)) | Err(_) => {
                    return finish(LocalLlmSlot::Ungated(Ungated::WaitExpired)).await;
                }
            }
        }
    };

    let lease = match fleet {
        None => None,
        Some(f) => match f.acquire(deadline, report).await {
            FleetAcquire::Leased(lease) => Some(lease),
            FleetAcquire::Unavailable => None,
            FleetAcquire::WaitExpired => {
                drop(permit);
                return finish(LocalLlmSlot::Ungated(Ungated::WaitExpired)).await;
            }
        },
    };
    finish(LocalLlmSlot::Held(Admitted {
        _local: permit,
        _fleet: lease,
    }))
    .await
}

/// [`admit`] on the process gate alone, with a wait report.
pub async fn acquire_reporting_from<W: QueueWaitObserver>(
    permits: Option<&Arc<Semaphore>>,
    wait_cap: Duration,
    wait: Option<&W>,
) -> (LocalLlmSlot, Duration) {
    admit(permits, None, wait_cap, wait).await
}

/// [`admit`] on the process gate alone, reporting nothing.
///
/// Exists so the BEHAVIOUR is testable: `process_gate()` and `max_in_flight()`
/// are process-global `OnceLock`s, so a suite that drove only the public
/// wrapper could exercise exactly one cap per test binary and could never
/// reach the disabled arm or the wait-expiry arm at all. Production has one
/// caller shape and it is [`acquire_process_slot`].
pub async fn acquire_from(
    permits: Option<&Arc<Semaphore>>,
    wait_cap: Duration,
) -> (LocalLlmSlot, Duration) {
    admit::<NoWaitObserver>(permits, None, wait_cap, None).await
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod gate_tests;
