//! The worker's half of RFC 0014 P2: time a job spends waiting for the
//! local-inference slot is not charged to its deadlines.
//!
//! One [`InferenceWaitLedger`] per dispatched job. The local-LLM gate
//! (`host::llm_gate`) tells it when a call starts and stops waiting; the job's
//! three wall-clock bounds read it:
//!
//! * the outer job timeout in the worker binary,
//! * the inner timeout around `call_async` in [`crate::runtime`],
//! * the wasmtime epoch callback's wall-clock bound ([`crate::epoch_budget`]).
//!
//! All three push their deadline back by [`InferenceWaitLedger::excluded`], so a
//! job's deadlines stand still while it waits — capped at
//! `LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS` in total, the same cap the controller
//! applies. The arithmetic is `talos_workflow_engine_core::WaitAccounting`, one
//! home for both processes.
//!
//! The ledger also carries an optional [`WaitNotifier`], through which the worker
//! binary tells the controller (a signed `JobProgress` on the reply inbox) so the
//! dispatcher's attempt window stands still too. Callers with no controller
//! waiting on them (`run_sandbox`, `test_module`, replay) pass no ledger at all
//! and keep their fixed deadlines.
//!
//! **Clock.** Instants come from `tokio::time::Instant::now()` converted to std,
//! so a test that pauses tokio's clock drives the ledger and the deadlines it
//! moves identically; in production the two clocks are the same clock.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use talos_workflow_job_protocol::{JobProgressState, WaitAccounting};

/// Told when a job starts and stops waiting for the local-inference slot.
///
/// Implemented by the worker binary, which signs and publishes a `JobProgress`.
/// A notification that cannot be delivered is the notifier's own concern: the
/// worker's deadlines move regardless, and the worst a lost message costs is
/// that the controller gives up on the attempt as it did before P2.
pub trait WaitNotifier: Send + Sync {
    fn notify(&self, state: JobProgressState) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// One job's waiting-for-the-slot account.
pub struct InferenceWaitLedger {
    account: Mutex<WaitAccounting>,
    notifier: Option<Arc<dyn WaitNotifier>>,
}

impl std::fmt::Debug for InferenceWaitLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InferenceWaitLedger")
            .field("excluded", &self.excluded())
            .field("notifier", &self.notifier.is_some())
            .finish()
    }
}

fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

impl InferenceWaitLedger {
    /// A ledger with the production cap.
    #[must_use]
    pub fn new(notifier: Option<Arc<dyn WaitNotifier>>) -> Self {
        Self::with_account(WaitAccounting::new(), notifier)
    }

    /// A ledger over explicit accounting (tests set a small cap).
    #[must_use]
    pub fn with_account(account: WaitAccounting, notifier: Option<Arc<dyn WaitNotifier>>) -> Self {
        Self {
            account: Mutex::new(account),
            notifier,
        }
    }

    fn account(&self) -> std::sync::MutexGuard<'_, WaitAccounting> {
        // A poisoned lock can only come from a panic inside the few lines
        // below that hold it, none of which can panic; recover rather than
        // turn a deadline read into a job failure.
        self.account.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waiting time excluded from the job's deadlines so far.
    #[must_use]
    pub fn excluded(&self) -> Duration {
        self.account().excluded(now())
    }

    /// Whether the job is waiting right now.
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        self.account().is_waiting()
    }

    /// The job has started waiting for the slot. The account is updated BEFORE
    /// the notification, so the worker's own deadlines stop at the true start.
    pub async fn begin_wait(&self) {
        self.account().begin(now());
        if let Some(n) = &self.notifier {
            n.notify(JobProgressState::Waiting).await;
        }
    }

    /// The job has stopped waiting (slot granted, or the queue wait expired).
    pub async fn end_wait(&self) {
        self.account().end(now());
        if let Some(n) = &self.notifier {
            n.notify(JobProgressState::Admitted).await;
        }
    }
}

/// A job's deadline expired (the waiting-adjusted one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineElapsed;

impl std::fmt::Display for DeadlineElapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl std::error::Error for DeadlineElapsed {}

/// `tokio::time::timeout`, except that time the job spends waiting for the
/// local-inference slot (per `ledger`) does not count.
///
/// Without a ledger this IS `tokio::time::timeout`. With one, the deadline is
/// re-read every time it is reached: if a wait pushed it back, sleep again; if
/// not, it has elapsed. While a wait is open the deadline moves with the clock,
/// so this wakes once per remaining-time interval rather than spinning.
pub async fn with_pausable_deadline<F: Future>(
    timeout: Duration,
    ledger: Option<&InferenceWaitLedger>,
    fut: F,
) -> Result<F::Output, DeadlineElapsed> {
    let Some(ledger) = ledger else {
        return tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| DeadlineElapsed);
    };
    let base = tokio::time::Instant::now() + timeout;
    tokio::pin!(fut);
    loop {
        let deadline = base + ledger.excluded();
        tokio::select! {
            out = &mut fut => return Ok(out),
            () = tokio::time::sleep_until(deadline) => {
                if tokio::time::Instant::now() >= base + ledger.excluded() {
                    return Err(DeadlineElapsed);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "inference_wait_tests.rs"]
mod tests;
