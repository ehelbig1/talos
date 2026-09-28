//! The worker-side ledger and the pausable deadline, on tokio's paused clock.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[derive(Default)]
struct Recorder {
    waiting: AtomicUsize,
    admitted: AtomicUsize,
}

impl WaitNotifier for Recorder {
    fn notify(&self, state: JobProgressState) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match state {
            JobProgressState::Waiting => self.waiting.fetch_add(1, Ordering::SeqCst),
            JobProgressState::Admitted => self.admitted.fetch_add(1, Ordering::SeqCst),
        };
        Box::pin(async {})
    }
}

/// THE property. A job with 10 s of work and a 30 s deadline that spends 60 s
/// waiting for the slot in the middle still finishes: the wait is not charged.
#[tokio::test(start_paused = true)]
async fn a_wait_for_the_slot_does_not_count_against_the_deadline() {
    let ledger = InferenceWaitLedger::new(None);
    let job = async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        ledger.begin_wait().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        ledger.end_wait().await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        "done"
    };
    let out = with_pausable_deadline(Duration::from_secs(30), Some(&ledger), job).await;
    assert_eq!(out, Ok("done"));
    assert_eq!(ledger.excluded(), Duration::from_secs(60));
}

/// The control: the same job without a ledger times out, which is the
/// behaviour P2 replaces.
#[tokio::test(start_paused = true)]
async fn without_a_ledger_the_same_job_times_out() {
    let job = async {
        tokio::time::sleep(Duration::from_secs(70)).await;
        "done"
    };
    let out = with_pausable_deadline(Duration::from_secs(30), None, job).await;
    assert_eq!(out, Err(DeadlineElapsed));
}

/// Work still counts: a job that WORKS past its deadline times out whether or
/// not it waited earlier.
#[tokio::test(start_paused = true)]
async fn work_past_the_deadline_still_times_out() {
    let ledger = InferenceWaitLedger::new(None);
    let job = async {
        ledger.begin_wait().await;
        tokio::time::sleep(Duration::from_secs(20)).await;
        ledger.end_wait().await;
        tokio::time::sleep(Duration::from_secs(31)).await; // 31 s of work > 30 s
        "done"
    };
    let started = tokio::time::Instant::now();
    let out = with_pausable_deadline(Duration::from_secs(30), Some(&ledger), job).await;
    assert_eq!(out, Err(DeadlineElapsed));
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(50),
        "30 s of work + 20 s waited"
    );
}

/// Waiting past the cap is charged again: the cap bounds how long a job can be
/// held open by queueing.
#[tokio::test(start_paused = true)]
async fn waiting_beyond_the_cap_is_charged() {
    let ledger =
        InferenceWaitLedger::with_account(WaitAccounting::with_cap(Duration::from_secs(40)), None);
    let job = async {
        ledger.begin_wait().await;
        tokio::time::sleep(Duration::from_secs(500)).await;
        "never"
    };
    let started = tokio::time::Instant::now();
    let out = with_pausable_deadline(Duration::from_secs(30), Some(&ledger), job).await;
    assert_eq!(out, Err(DeadlineElapsed));
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(70),
        "30 s + the 40 s cap"
    );
}

#[tokio::test(start_paused = true)]
async fn the_notifier_hears_one_waiting_and_one_admitted_per_wait() {
    let rec = Arc::new(Recorder::default());
    let ledger = InferenceWaitLedger::new(Some(rec.clone()));
    ledger.begin_wait().await;
    assert!(ledger.is_waiting());
    tokio::time::sleep(Duration::from_secs(3)).await;
    ledger.end_wait().await;
    assert!(!ledger.is_waiting());
    assert_eq!(rec.waiting.load(Ordering::SeqCst), 1);
    assert_eq!(rec.admitted.load(Ordering::SeqCst), 1);
    assert_eq!(ledger.excluded(), Duration::from_secs(3));
}
