//! CONTROL for `embedding_gate_serial_backend`: the same burst against the
//! same one-at-a-time backend with the gate switched OFF
//! (`TALOS_EMBEDDING_MAX_IN_FLIGHT=0`), i.e. the behaviour before the gate.
//! Calls spend their timeout queued inside the backend and fail. Without
//! this, the sibling's "every call succeeds" would prove nothing about the
//! gate.
//!
//! ONE test in this binary: the client reads its configuration once per
//! process.

mod embedding_mock;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use talos_memory::embedding::{self, CallOutcome, CallReport, GateOutcome};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_the_gate_the_same_burst_times_out_in_the_backends_queue() {
    const DIMS: usize = 4;
    let mock = embedding_mock::start(Duration::from_millis(300), DIMS).await;
    embedding_mock::configure(&mock.url, DIMS, 1, Some("0"));
    let reports: Arc<Mutex<Vec<CallReport>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = reports.clone();
    embedding::set_call_observer(Arc::new(move |r| sink.lock().unwrap().push(r)));

    let calls: Vec<_> = (0..6)
        .map(|i| {
            tokio::spawn(async move {
                embedding::generate_embedding(&format!("distinct text number {i}"), true).await
            })
        })
        .collect();
    let mut results: Vec<Option<Vec<f32>>> = Vec::new();
    for call in calls {
        results.push(call.await.expect("task"));
    }

    let failed = results.iter().filter(|r| r.is_none()).count();
    assert!(
        failed >= 1,
        "with no gate at least one call must be lost to the backend's queue: {:?}",
        results.iter().map(Option::is_some).collect::<Vec<_>>()
    );
    assert!(
        mock.peak_in_backend.load(Ordering::SeqCst) > 1,
        "ungated calls reach the backend together"
    );
    // The lost calls were retried into the same queue.
    assert!(mock.received.load(Ordering::SeqCst) > 6);
    let reports = reports.lock().unwrap();
    assert_eq!(reports.len(), 6);
    assert!(reports.iter().all(|r| r.gate == GateOutcome::Ungated));
    assert_eq!(
        reports
            .iter()
            .filter(|r| r.outcome == CallOutcome::Unavailable)
            .count(),
        failed
    );
}
