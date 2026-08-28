//! Compute-bound cancellation: preempting a guest that makes no host calls.
//!
//! # The gap this closes
//!
//! PR #690 wired operator cancellation end-to-end: the controller broadcasts a
//! signed `CancelCommand`, the worker resolves it through
//! [`crate::cancel_registry`] and flips the job-scoped `Arc<AtomicBool>` that
//! every `TalosContext::is_cancelled()` guard reads. That reaches ~20 call
//! sites — and every one of them sits on a **host-call boundary**.
//!
//! A guest doing pure computation crosses no such boundary. It ignored
//! cancellation entirely and burned a worker slot until its fuel ran out or
//! its wall-clock timeout fired. `tokio::time::timeout` cannot help either: a
//! non-yielding sync loop inside `call_async` never returns to the executor.
//!
//! # The mechanism
//!
//! `Config::epoch_interruption(true)` is already on (see the engine-config
//! block in [`crate::runtime`]), and Cranelift therefore emits an epoch check
//! at **every loop back-edge and every function entry** — see
//! `wasmtime-internal-cranelift`'s `translate_loop_header` /
//! `epoch_function_entry`. Those checks need no host call, which is exactly
//! the property the compute-bound case needs.
//!
//! Before this module the store used wasmtime's DEFAULT deadline behaviour:
//! arm `set_epoch_deadline(total)` once, trap when it trips. The deadline was
//! therefore consulted exactly once per job, at the very end of its budget.
//!
//! Here the same total budget is handed out in small slices through
//! [`wasmtime::Store::epoch_deadline_callback`], so the runtime re-enters host
//! code roughly every [`CANCEL_CHECK_SLICE_TICKS`] ticks of guest execution and
//! can read the cancel flag. Cancelled ⇒ trap immediately. Not cancelled ⇒
//! extend by the next slice.
//!
//! `epoch_deadline_callback` is a **`Store`-level** setting. Nothing about
//! `Config` changes, so the AOT cache fingerprint (`TALOSV3`) is untouched and
//! no compiled blob in the fleet needs recompiling.
//!
//! # Why the budget cannot grow
//!
//! [`EpochBudget`] owns a `remaining` tick count that is **only ever
//! decremented, by exactly the amount granted**. There is no method that
//! raises it and the field is private, so "the extensions sum to more than the
//! original budget" is not a rule a future editor can break by accident — it
//! is the only arithmetic the type permits. `first_slice + Σ Continue(d) ==
//! total` is asserted directly by
//! `slices_sum_to_exactly_the_original_budget`.
//!
//! # Why a wall-clock bound as well
//!
//! Ticks measure the ENGINE epoch, which advances on a background ticker
//! whether or not the guest is running. A guest suspended in a long host call
//! accumulates overshoot: under the single-shot default it traps the instant it
//! resumes, whereas a naive slicing scheme would hand it a fresh slice measured
//! from *now* and could stretch the job far past its configured timeout. The
//! `wall_clock_expired` input closes that: the effective deadline is
//! `min(tick budget, armed_at + timeout)`, which reproduces the single-shot
//! behaviour for a suspended guest and is identical for a compute-bound one.
//! It costs one `Instant::now()` per callback — no allocation, no lock, no
//! logging — at most ten per second of guest execution.
//!
//! # Cost on the non-cancelled path
//!
//! An `Ordering::Relaxed` atomic load, one `Instant` comparison, one
//! subtraction. The callback body allocates nothing and logs nothing; the only
//! allocation in this module is the abort message, built once, on the path that
//! is about to trap the guest anyway.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wasmtime::{Store, UpdateDeadline};

use crate::context::TalosContext;

/// Epoch ticks handed out per slice.
///
/// One tick is [`crate::runtime::EPOCH_TICK_INTERVAL_MS`] (100 ms), so the
/// worst-case latency between an operator's cancel landing on the flag and the
/// guest being trapped is one tick of guest execution plus the ticker's own
/// granularity. Raising this trades cancellation promptness for fewer
/// (already negligible) cold-path libcalls; it can never change the TOTAL
/// budget, only how finely it is subdivided.
pub(crate) const CANCEL_CHECK_SLICE_TICKS: u64 = 1;

/// Stable marker stamped into the abort error the callback raises.
///
/// The single-node trap handler in [`crate::runtime`] deliberately collapses
/// unrecognised traps to the opaque `"WASM trap encountered"` (a wasmtime error
/// can carry guest backtrace addresses, which must not reach a caller). Without
/// a marker to match on, an operator-requested abort would arrive looking
/// exactly like a random guest trap. This is matched against BOTH the `Display`
/// and `Debug` renderings of the error, the same way the fuel check next to it
/// is, because wasmtime attaches the wasm backtrace as error CONTEXT and the
/// original message can end up in the chain rather than at the top.
///
/// It is not guest-influenceable: the value compared against is wasmtime's own
/// error for the `call_async` that failed. Guest-authored text arrives on a
/// different channel (captured WASI stderr) and is never matched here.
pub(crate) const CANCEL_PREEMPT_MARKER: &str = "talos:cancel-preempt";

/// The operator-facing message for a job aborted mid-computation by a cancel.
///
/// Two properties are load-bearing:
///
/// * It carries `[reason_class=cancelled]`, which
///   [`crate::runtime::is_transient_error_text`] and
///   `talos_retry_intelligence::classify_error` both already treat as
///   NON-transient (see [`crate::reason_class::NON_TRANSIENT`]). A cancelled
///   job must not be retried in-worker or re-dispatched by the controller.
/// * It contains neither `"timed out"` nor `"timeout"` nor `"fuel"`, so it can
///   never be read — by an operator or by either classifier — as the genuine
///   wall-clock timeout or a fuel exhaustion. "We killed this" and "this ran
///   too long" are distinguishable from the message alone.
pub const CANCEL_PREEMPT_MESSAGE: &str =
    "WASM execution aborted mid-computation: the execution was cancelled by an operator \
     (talos:cancel-preempt) [reason_class=cancelled]";

/// What the epoch-deadline callback decided. Split from the callback itself so
/// the policy is unit-testable without a wasm runtime, an engine, or a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EpochDecision {
    /// The job's cancel flag is set — trap NOW with [`CANCEL_PREEMPT_MESSAGE`].
    AbortCancelled,
    /// The budget is spent — trap exactly as wasmtime's default
    /// (`epoch_deadline_trap`) behaviour would have.
    AbortExhausted,
    /// Extend the deadline by this many ticks and keep running.
    Continue(u64),
}

/// A strictly-decreasing epoch-tick budget.
///
/// Constructed with the job's whole budget; hands back a first slice to arm on
/// the `Store` and keeps the remainder. See the module docs for why the
/// non-growth property is structural rather than conventional.
#[derive(Debug)]
pub(crate) struct EpochBudget {
    /// Ticks not yet granted. Monotonically non-increasing; nothing in this
    /// type raises it.
    remaining: u64,
    /// Ticks handed out per slice.
    slice: u64,
}

impl EpochBudget {
    /// Split `total` into `(first_slice, budget)`.
    ///
    /// `first_slice` is what the caller arms on the `Store`; `budget` holds
    /// everything left. `total` comes from
    /// [`crate::runtime::epoch_ticks_for_timeout`], which never returns 0.
    /// A `total` of 0 would arm a deadline that trips at the first check, so
    /// it is floored at one tick — matching the pre-callback behaviour, where
    /// `set_epoch_deadline(0)` was likewise never passed.
    pub(crate) fn new(total: u64) -> (u64, Self) {
        Self::with_slice(total, CANCEL_CHECK_SLICE_TICKS)
    }

    /// [`Self::new`] with an explicit slice size, so tests can exercise
    /// multi-tick slices and remainder handling without depending on the
    /// production constant.
    pub(crate) fn with_slice(total: u64, slice: u64) -> (u64, Self) {
        let slice = slice.max(1);
        let total = total.max(1);
        let first = total.min(slice);
        (
            first,
            Self {
                remaining: total - first,
                slice,
            },
        )
    }

    /// Ticks not yet granted. Test-facing view of the invariant.
    #[cfg(test)]
    pub(crate) fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Grant the next slice, shrinking the budget by exactly what is granted.
    /// Returns 0 once the budget is spent.
    fn take(&mut self) -> u64 {
        let granted = self.remaining.min(self.slice);
        self.remaining -= granted;
        granted
    }

    /// The whole policy, as a pure function of the two observations the
    /// callback makes.
    ///
    /// Precedence is deliberate: **cancellation wins over exhaustion**. When an
    /// operator's cancel lands in the same slice that spends the last tick, the
    /// job must be reported as killed, not as having run too long — the two are
    /// different operational facts and the report is the only place they are
    /// distinguishable.
    pub(crate) fn decide(&mut self, cancelled: bool, wall_clock_expired: bool) -> EpochDecision {
        if cancelled {
            return EpochDecision::AbortCancelled;
        }
        if wall_clock_expired {
            return EpochDecision::AbortExhausted;
        }
        match self.take() {
            0 => EpochDecision::AbortExhausted,
            granted => EpochDecision::Continue(granted),
        }
    }
}

/// Arm `store`'s epoch deadline for `timeout`, with cancellation preemption.
///
/// **The single chokepoint.** Every `Store` the runtime executes a guest on is
/// armed here, so no dispatch shape can drift into being un-preemptible. That
/// matters concretely: #690 was widened to pipelines precisely so cancellation
/// would not be PROTOCOL-DEPENDENT, and arming only the single-node stores
/// would have reintroduced that asymmetry one layer down.
///
/// The flag the callback reads is `store.data().cancelled` — read out of the
/// context the store already owns rather than passed in alongside it. That is
/// deliberate: it is by construction the SAME `Arc<AtomicBool>` the job
/// registered with [`crate::cancel_registry`], so no call site can hand this
/// function a second, unreachable flag. (#689 was a lifetime mismatch of
/// exactly that shape — a flag whose lifetime did not match the job's.)
///
/// For stores whose context is not registered with the cancel registry
/// (`run_sandbox` / `test_module` / the AOT path all pass no execution id), the
/// flag simply stays `false` for the life of the job and the behaviour is the
/// pre-callback behaviour, tick for tick.
pub(crate) fn arm_epoch_deadline(store: &mut Store<TalosContext>, timeout: Duration) {
    let total = crate::runtime::epoch_ticks_for_timeout(timeout);
    // Same Arc as the registry's — see the doc comment above.
    let cancelled: Arc<AtomicBool> = store.data().cancelled.clone();
    let metrics = store.data().metrics.clone();
    let wall_clock_deadline = Instant::now() + timeout;

    let (first_slice, mut budget) = EpochBudget::new(total);
    store.set_epoch_deadline(first_slice);

    store.epoch_deadline_callback(move |_ctx| {
        // Hot path: one relaxed atomic load, one Instant compare, one
        // subtraction. No allocation, no lock, no logging.
        let decision = budget.decide(
            cancelled.load(Ordering::Relaxed),
            Instant::now() >= wall_clock_deadline,
        );
        match decision {
            EpochDecision::Continue(ticks) => Ok(UpdateDeadline::Continue(ticks)),
            // Byte-for-byte what wasmtime's default (no-callback) behaviour
            // returns for an expired deadline: `Trap::Interrupt`.
            EpochDecision::AbortExhausted => Ok(UpdateDeadline::Interrupt),
            EpochDecision::AbortCancelled => {
                // Cold path — fires at most once per job, immediately before
                // the guest is trapped.
                if let Some(m) = &metrics {
                    m.record_execution_preempted();
                }
                // `Error::msg` over a `&'static str`: the wasmtime-native
                // error type, no allocation, no formatting.
                Err(wasmtime::Error::msg(CANCEL_PREEMPT_MESSAGE))
            }
        }
    });
}

/// Whether an error is the abort this module raised.
///
/// Checks both renderings for the reason given on [`CANCEL_PREEMPT_MARKER`].
/// `wasmtime::Error`'s plain `Display` prints only the OUTERMOST message (the
/// source chain needs `{:#}` or `Debug`), and wasmtime attaches the wasm
/// backtrace as context — so matching only on `Display` would miss the abort
/// exactly when a backtrace was captured. `Debug` renders the full `Caused by`
/// chain and closes that.
///
/// Generic over the two error types the runtime holds at the four trap arms:
/// `wasmtime::Error` (what `call_async` returns in wasmtime 47) and
/// `anyhow::Error` (what the surrounding runtime code uses). One recogniser so
/// the two cannot drift.
pub(crate) fn is_cancel_preempt_error<E>(err: &E) -> bool
where
    E: std::fmt::Display + std::fmt::Debug + ?Sized,
{
    format!("{err}").contains(CANCEL_PREEMPT_MARKER)
        || format!("{err:?}").contains(CANCEL_PREEMPT_MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE budget invariant. Every slice the type ever grants, summed with the
    /// slice armed on the store, must equal the original budget exactly — not
    /// "about", not "at most". A bug in the other direction lets a guest run
    /// forever, which is strictly worse than the status quo this change
    /// replaces.
    #[test]
    fn slices_sum_to_exactly_the_original_budget() {
        for (total, slice) in [
            (1u64, 1u64),
            (2, 1),
            (10, 1),
            (1200, 1),
            (7, 3),
            (9, 3),
            (100, 7),
            (1, 5),
            (6_048_000, 1),
        ] {
            let (first, mut budget) = EpochBudget::with_slice(total, slice);
            let mut granted = first;
            loop {
                match budget.decide(false, false) {
                    EpochDecision::Continue(d) => {
                        assert!(d > 0, "a Continue must advance the deadline");
                        granted += d;
                    }
                    EpochDecision::AbortExhausted => break,
                    EpochDecision::AbortCancelled => unreachable!("not cancelled"),
                }
                assert!(
                    granted <= total,
                    "budget overrun at total={total} slice={slice}: granted {granted}"
                );
            }
            assert_eq!(
                granted, total,
                "slices must sum to exactly the original budget (total={total}, slice={slice})"
            );
            assert_eq!(budget.remaining(), 0);
        }
    }

    /// The counter only ever decreases. Asserted over the whole life of a
    /// budget rather than at the endpoints, so a "top up on some condition"
    /// regression cannot hide in the middle.
    #[test]
    fn remaining_never_increases() {
        let (_first, mut budget) = EpochBudget::with_slice(50, 3);
        let mut prev = budget.remaining();
        for _ in 0..100 {
            let _ = budget.decide(false, false);
            let now = budget.remaining();
            assert!(now <= prev, "remaining rose from {prev} to {now}");
            prev = now;
        }
    }

    /// An exhausted budget stays exhausted. Calling the callback again after
    /// the trap decision must not resurrect the job.
    #[test]
    fn an_exhausted_budget_never_grants_again() {
        let (_first, mut budget) = EpochBudget::with_slice(3, 1);
        while budget.decide(false, false) != EpochDecision::AbortExhausted {}
        for _ in 0..10 {
            assert_eq!(budget.decide(false, false), EpochDecision::AbortExhausted);
        }
    }

    /// A one-tick budget is fully consumed by the slice armed on the store, so
    /// the first callback trips the trap. This is the shortest job the runtime
    /// can express (`epoch_ticks_for_timeout` floors at 1).
    #[test]
    fn a_one_tick_budget_arms_everything_and_traps_on_first_callback() {
        let (first, mut budget) = EpochBudget::new(1);
        assert_eq!(first, 1);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.decide(false, false), EpochDecision::AbortExhausted);
    }

    /// `epoch_ticks_for_timeout` never returns 0, but the floor is asserted
    /// here anyway: arming `set_epoch_deadline(0)` would trap at the first
    /// check point, killing every job instantly.
    #[test]
    fn a_zero_total_is_floored_to_one_tick_not_armed_at_zero() {
        let (first, _budget) = EpochBudget::new(0);
        assert_eq!(first, 1, "arming 0 ticks would trap at the first check");
    }

    /// Cancellation aborts on the very next callback regardless of how much
    /// budget is left — that is the whole point of the change.
    #[test]
    fn cancellation_aborts_immediately_with_budget_remaining() {
        let (_first, mut budget) = EpochBudget::with_slice(1_000_000, 1);
        assert_eq!(budget.decide(false, false), EpochDecision::Continue(1));
        assert_eq!(budget.decide(true, false), EpochDecision::AbortCancelled);
        assert!(
            budget.remaining() > 900_000,
            "abort must not spend the budget"
        );
    }

    /// Cancellation outranks exhaustion. A cancel landing in the same slice
    /// that spends the last tick must be REPORTED as a cancellation: "we
    /// killed this" and "this ran too long" are different operational facts.
    #[test]
    fn cancellation_outranks_exhaustion_and_wall_clock() {
        let (_first, mut budget) = EpochBudget::with_slice(1, 1);
        assert_eq!(budget.remaining(), 0, "budget is already spent");
        assert_eq!(budget.decide(true, true), EpochDecision::AbortCancelled);
    }

    /// The wall-clock bound is what keeps a guest suspended in a long host call
    /// from being handed fresh slices measured from its resume point. Without
    /// it the sliced scheme would run such a job far past its configured
    /// timeout — a behaviour change for uncancelled jobs, which this change
    /// must not have.
    #[test]
    fn an_expired_wall_clock_traps_even_with_ticks_remaining() {
        let (_first, mut budget) = EpochBudget::with_slice(1_000_000, 1);
        assert_eq!(budget.decide(false, true), EpochDecision::AbortExhausted);
    }

    /// The abort message must be readable as a cancellation and NOT as a
    /// timeout or a fuel exhaustion — by an operator and by both classifiers.
    #[test]
    fn the_abort_message_is_distinguishable_from_a_timeout() {
        let lower = CANCEL_PREEMPT_MESSAGE.to_lowercase();
        assert!(lower.contains("cancel"), "{CANCEL_PREEMPT_MESSAGE}");
        assert!(
            !lower.contains("timed out") && !lower.contains("timeout"),
            "a cancellation must not read as a wall-clock timeout: {CANCEL_PREEMPT_MESSAGE}"
        );
        assert!(
            !lower.contains("fuel"),
            "a cancellation must not read as fuel exhaustion: {CANCEL_PREEMPT_MESSAGE}"
        );
        assert!(
            CANCEL_PREEMPT_MESSAGE.contains(CANCEL_PREEMPT_MARKER),
            "the trap handler matches on the marker; it must be present in the message"
        );
    }

    /// Neither classifier may retry a preempted job. The controller-side twin
    /// (`talos_retry_intelligence::classify_error`) keys on the same
    /// `[reason_class=cancelled]` token, which
    /// `crate::reason_class::NON_TRANSIENT` already contains.
    #[test]
    fn the_abort_message_classifies_non_transient() {
        assert!(
            CANCEL_PREEMPT_MESSAGE
                .contains(&format!("reason_class={}", crate::reason_class::CANCELLED)),
            "the message must carry the cancelled reason class"
        );
        assert!(
            !crate::runtime::is_transient_error_text(CANCEL_PREEMPT_MESSAGE),
            "a preempted job must never be retried in-worker"
        );
    }

    /// The trap handler's recogniser must fire on both renderings, because
    /// wasmtime attaches the wasm backtrace as error CONTEXT — which moves the
    /// original message out of the top-level `Display`.
    #[test]
    fn the_preempt_recogniser_sees_the_error_through_added_context() {
        let bare = anyhow::anyhow!("{}", CANCEL_PREEMPT_MESSAGE);
        assert!(is_cancel_preempt_error(&bare));

        // Also the wasmtime-native error type the four trap arms actually
        // hold — `wasmtime::Error` is a DISTINCT type from `anyhow::Error` in
        // wasmtime 47, and this is exactly what the callback returns.
        assert!(is_cancel_preempt_error(&wasmtime::Error::msg(
            CANCEL_PREEMPT_MESSAGE
        )));

        let wrapped = bare.context("wasm trap: wasm backtrace: 0x1234");
        assert!(
            is_cancel_preempt_error(&wrapped),
            "a preempt error wrapped in wasmtime's backtrace context must still be recognised"
        );

        assert!(!is_cancel_preempt_error(&anyhow::anyhow!(
            "wasm trap: wasm `unreachable` instruction executed"
        )));
        assert!(!is_cancel_preempt_error(&anyhow::anyhow!(
            "WASM execution timed out after 120s"
        )));
    }

    /// The tick budget handed to the callback is exactly what the pre-callback
    /// code armed in one shot — the slicing subdivides that number, it does not
    /// recompute it.
    #[test]
    fn the_total_budget_is_the_same_number_the_single_shot_path_armed() {
        for secs in [1u64, 10, 30, 120, 3600] {
            let d = Duration::from_secs(secs);
            let total = crate::runtime::epoch_ticks_for_timeout(d);
            let (first, mut budget) = EpochBudget::new(total);
            let mut granted = first;
            while let EpochDecision::Continue(x) = budget.decide(false, false) {
                granted += x;
            }
            assert_eq!(
                granted, total,
                "a {secs}s job must be granted exactly {total} ticks in total"
            );
        }
    }
}
