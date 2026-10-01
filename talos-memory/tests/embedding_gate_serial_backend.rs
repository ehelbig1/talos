//! The in-flight gate against a backend that serves one request at a time
//! (2026-10-01). Drives the PRODUCTION `generate_embedding`.
//!
//! Six calls arrive at once; the backend takes 300 ms each; the client's
//! per-attempt timeout is 1 s. Sent all at once, the fourth, fifth and sixth
//! spend their whole timeout queued inside the backend — that is the
//! sibling binary `embedding_gate_disabled_control`, where calls fail. Here
//! the gate is on (its default), so each call's timeout covers its own
//! 300 ms and every call succeeds.
//!
//! ONE test in this binary: the client reads its configuration once per
//! process.

mod embedding_mock;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use talos_memory::embedding::{self, CallOutcome, CallReport, GateOutcome};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_call_in_a_burst_succeeds_and_the_backend_sees_one_at_a_time() {
    const DIMS: usize = 4;
    let mock = embedding_mock::start(Duration::from_millis(300), DIMS).await;
    embedding_mock::configure(&mock.url, DIMS, 1, None);
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

    assert!(
        results
            .iter()
            .all(|r| r.as_ref().is_some_and(|v| v.len() == DIMS)),
        "every call must get its vector: {:?}",
        results.iter().map(Option::is_some).collect::<Vec<_>>()
    );
    assert_eq!(
        mock.peak_in_backend.load(Ordering::SeqCst),
        1,
        "the gate must hand the backend one request at a time"
    );
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        6,
        "no retries were needed"
    );

    let seen: Vec<CallReport> = reports.lock().unwrap().clone();
    assert_eq!(seen.len(), 6);
    assert!(seen
        .iter()
        .all(|r| r.gate == GateOutcome::Acquired && r.outcome == CallOutcome::Ok));
    // The last call queued for about five service times; its own service
    // time stayed one service time, well inside the 1 s timeout.
    let longest_wait = seen.iter().map(|r| r.queue_wait).max().unwrap();
    assert!(
        longest_wait >= Duration::from_millis(1_200),
        "{longest_wait:?}"
    );
    // …while no call's own time reached the 1 s timeout, although the last
    // one was in flight for longer than that.
    assert!(
        seen.iter().all(|r| r.service < Duration::from_secs(1)),
        "service time must not include the queue: {:?}",
        seen.iter().map(|r| r.service).collect::<Vec<_>>()
    );

    // A repeat of a text already embedded is a cache hit: no provider call,
    // no report.
    let again = embedding::generate_embedding("distinct text number 0", true).await;
    assert!(again.is_some());
    assert_eq!(mock.received.load(Ordering::SeqCst), 6);
    assert_eq!(reports.lock().unwrap().len(), 6);
}
