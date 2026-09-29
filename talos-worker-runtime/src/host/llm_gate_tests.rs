//! The worker's half of the local-LLM gate: a call that QUEUES records its
//! wait on the job's `InferenceWaitLedger` (RFC 0014 P2a). The gate itself,
//! and its own tests, live in `talos_local_inference::gate`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use super::{acquire_reporting_from, LocalLlmSlot, Ungated};

fn sem(n: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(n))
}

#[derive(Default)]
struct Heard {
    waiting: AtomicUsize,
    admitted: AtomicUsize,
}

impl crate::inference_wait::WaitNotifier for Heard {
    fn notify(
        &self,
        state: talos_workflow_job_protocol::JobProgressState,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        match state {
            talos_workflow_job_protocol::JobProgressState::Waiting => {
                self.waiting.fetch_add(1, Ordering::SeqCst)
            }
            talos_workflow_job_protocol::JobProgressState::Admitted => {
                self.admitted.fetch_add(1, Ordering::SeqCst)
            }
        };
        Box::pin(async {})
    }
}

/// A free slot is taken without a word: no wait, nothing excluded, nothing
/// reported. This is 94 % of local calls on the reference fleet.
#[tokio::test(start_paused = true)]
async fn a_free_slot_records_no_wait() {
    let heard = Arc::new(Heard::default());
    let ledger = crate::inference_wait::InferenceWaitLedger::new(Some(heard.clone()));
    let s = sem(1);
    let (slot, waited) =
        acquire_reporting_from(Some(&s), Duration::from_secs(120), Some(&ledger)).await;
    assert!(matches!(slot, LocalLlmSlot::Held(_)));
    assert_eq!(waited, Duration::ZERO);
    assert_eq!(ledger.excluded(), Duration::ZERO);
    assert_eq!(heard.waiting.load(Ordering::SeqCst), 0);
    assert_eq!(heard.admitted.load(Ordering::SeqCst), 0);
}

/// A queued call opens a wait when it starts queueing and closes it when it
/// gets the slot: the ledger excludes exactly the time spent queued, and the
/// notifier hears one `waiting` and one `admitted`.
#[tokio::test(start_paused = true)]
async fn a_queued_call_records_exactly_its_wait() {
    let heard = Arc::new(Heard::default());
    let ledger = Arc::new(crate::inference_wait::InferenceWaitLedger::new(Some(
        heard.clone(),
    )));
    let s = sem(1);
    let holder = s.clone().acquire_owned().await.unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(45)).await;
        drop(holder);
    });
    let (slot, waited) =
        acquire_reporting_from(Some(&s), Duration::from_secs(120), Some(&*ledger)).await;
    release.await.unwrap();
    assert!(matches!(slot, LocalLlmSlot::Held(_)));
    assert_eq!(waited, Duration::from_secs(45));
    assert_eq!(ledger.excluded(), Duration::from_secs(45));
    assert!(!ledger.is_waiting());
    assert_eq!(heard.waiting.load(Ordering::SeqCst), 1);
    assert_eq!(heard.admitted.load(Ordering::SeqCst), 1);
}

/// A queue wait that expires still counts as waited, and still closes the
/// wait, so the controller does not hold the attempt open on a call that is
/// now running ungated.
#[tokio::test(start_paused = true)]
async fn an_expired_queue_wait_is_excluded_and_closed() {
    let heard = Arc::new(Heard::default());
    let ledger = crate::inference_wait::InferenceWaitLedger::new(Some(heard.clone()));
    let s = sem(1);
    let _holder = s.clone().acquire_owned().await.unwrap();
    let (slot, _) = acquire_reporting_from(Some(&s), Duration::from_secs(120), Some(&ledger)).await;
    assert!(matches!(slot, LocalLlmSlot::Ungated(Ungated::WaitExpired)));
    assert_eq!(ledger.excluded(), Duration::from_secs(120));
    assert!(!ledger.is_waiting());
    assert_eq!(heard.admitted.load(Ordering::SeqCst), 1);
}

/// RFC 0014 P4b: both local call sites hand the gate the model they will ask
/// for, so the fleet queue can count model switches. A TEXTUAL pin: the fleet
/// queue is not installed in this test binary, so no behavioural test here can
/// see the argument.
#[test]
fn both_local_call_sites_pass_the_model_to_the_gate() {
    for (file, src) in [
        ("llm.rs", include_str!("llm.rs")),
        ("llm_tools.rs", include_str!("llm_tools.rs")),
    ] {
        let at = src
            .find("acquire_local_llm_slot(")
            .unwrap_or_else(|| panic!("{file}: no gate call"));
        let args: String = src[at..at + 200].split_whitespace().collect();
        assert!(
            args.starts_with("acquire_local_llm_slot(self.inference_wait.as_deref(),&model,)"),
            "{file}: the gate call does not pass the model: {args}"
        );
    }
}
