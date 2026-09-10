//! In-flight gate for LOCAL (Ollama) LLM exchanges.
//!
//! ## The defect this closes
//!
//! `LOCAL_LLM_EXCHANGE_TIMEOUT_SECS` (60 s) is documented on
//! [`crate::host::limits`] as a bound on **one call**: *"a cold-start with a
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
//! * **Not a bound on the controller.** `talos_llm::OllamaClient` — memory
//!   consolidation, graph-RAG entity extraction, evaluation — runs in the
//!   controller process and is not gated here. Those callers already sit
//!   behind their own in-flight caps (`memory_rpc::MAX_IN_FLIGHT` = 16,
//!   `graph_rpc` = 8) but nothing relates those caps to this one.
//! * **Not applied to external providers.** Anthropic / OpenAI / Gemini serve
//!   requests in parallel and bill per token; serializing them would be a
//!   straight latency regression for no benefit. The gate keys on exactly the
//!   `is_local` flag the call sites already compute to choose the HTTP client.
//! * **Not a bound on streaming.** `llm_streaming.rs` holds a long-lived SSE
//!   connection whose whole point is to stay open; a permit held for the life
//!   of a stream would deadlock the two gated paths behind it.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Simultaneous LOCAL LLM exchanges permitted per worker process.
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
pub(crate) const DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT: usize = 1;

/// Override for [`DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT`]. `0` disables the gate
/// entirely (every call proceeds immediately, pre-gate behaviour); an
/// unparseable or empty value falls back to the default rather than to 0,
/// because a typo must not silently switch a control off.
pub(crate) const MAX_IN_FLIGHT_ENV: &str = "TALOS_LOCAL_LLM_MAX_IN_FLIGHT";

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
pub(crate) const LOCAL_LLM_QUEUE_WAIT_SECS: u64 = 120;

/// Why a call is running without a permit.
///
/// Kept as an enum rather than a bool so the two reasons cannot be conflated
/// in the metric: `Disabled` is a deployment that turned the control off and
/// is a permanent steady state, `WaitExpired` is a queue that did not drain
/// and is a real load signal. Collapsing them would put a configuration
/// choice and a saturation event in one series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ungated {
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
pub(crate) enum LocalLlmSlot {
    Held(#[allow(dead_code)] OwnedSemaphorePermit),
    Ungated(Ungated),
}

/// Label for [`crate::metrics::RuntimeMetrics::record_llm_gate`]. Closed,
/// compile-time set — never a caller-derived value.
impl LocalLlmSlot {
    pub(crate) fn outcome_label(&self) -> &'static str {
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
pub(crate) const GATE_OUTCOME_LABELS: [&str; 3] = ["acquired", "disabled", "wait_expired"];

/// Parse the cap from a raw env value. Pure, so the parsing rule is testable
/// without the process-global latch below.
///
/// A missing, empty or UNPARSEABLE value falls back to the default rather than
/// to 0. A typo must not silently switch a control off — that is the
/// fail-in-the-reassuring-direction shape this repo keeps finding.
pub(crate) fn resolve_max_in_flight(raw: Option<&str>) -> usize {
    raw.map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT)
}

/// Resolved cap. Read once — the semaphore below latches with it, so a
/// mid-process env change could not take effect anyway and pretending
/// otherwise would be worse than saying so.
pub(crate) fn max_in_flight() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| resolve_max_in_flight(std::env::var(MAX_IN_FLIGHT_ENV).ok().as_deref()))
}

/// The process's gate, or `None` when the cap is 0 (gate disabled).
fn gate_permits() -> Option<&'static Arc<Semaphore>> {
    static SEM: OnceLock<Option<Arc<Semaphore>>> = OnceLock::new();
    SEM.get_or_init(|| match max_in_flight() {
        0 => None,
        n => Some(Arc::new(Semaphore::new(n))),
    })
    .as_ref()
}

/// Take a local-LLM slot, waiting up to [`LOCAL_LLM_QUEUE_WAIT_SECS`].
///
/// Returns the slot and how long the wait took. **Call this BEFORE starting
/// the exchange timeout**: the entire point is that queue time is not charged
/// to a budget that is supposed to measure one call's own service time.
pub(crate) async fn acquire_local_llm_slot() -> (LocalLlmSlot, Duration) {
    acquire_from(
        gate_permits(),
        Duration::from_secs(LOCAL_LLM_QUEUE_WAIT_SECS),
    )
    .await
}

/// The whole decision, with the semaphore and the wait cap supplied.
///
/// Exists so the BEHAVIOUR is testable: `gate_permits()` and `max_in_flight()`
/// are process-global `OnceLock`s, so a suite that drove only the public
/// wrapper could exercise exactly one cap per test binary and could never
/// reach the disabled arm or the wait-expiry arm at all. Production has one
/// caller shape and it is the wrapper above.
pub(crate) async fn acquire_from(
    permits: Option<&Arc<Semaphore>>,
    wait_cap: Duration,
) -> (LocalLlmSlot, Duration) {
    let Some(sem) = permits else {
        return (LocalLlmSlot::Ungated(Ungated::Disabled), Duration::ZERO);
    };
    let started = Instant::now();
    let slot = match tokio::time::timeout(wait_cap, sem.clone().acquire_owned()).await {
        Ok(Ok(permit)) => LocalLlmSlot::Held(permit),
        // `acquire_owned` errors only when the semaphore is CLOSED, and
        // nothing in this process ever closes it. Rendered as `WaitExpired`
        // rather than unwrapped, because a panic inside a host function
        // unwinds the whole job — and rather than as `Disabled`, which would
        // report a closed semaphore as an operator's configuration choice.
        Ok(Err(_)) | Err(_) => LocalLlmSlot::Ungated(Ungated::WaitExpired),
    };
    (slot, started.elapsed())
}

#[cfg(test)]
#[path = "llm_gate_tests.rs"]
mod llm_gate_tests;
