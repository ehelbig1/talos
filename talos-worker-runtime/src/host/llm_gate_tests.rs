//! Behaviour of the local-LLM in-flight gate.
//!
//! Every case drives [`super::acquire_from`] — the function
//! [`super::acquire_local_llm_slot`] delegates to — with its own semaphore,
//! because `gate_permits()` and `max_in_flight()` are process-global
//! `OnceLock`s: a suite that drove only the public wrapper could exercise
//! exactly ONE cap per test binary and could never reach the disabled arm or
//! the wait-expiry arm at all.
//!
//! What is NOT proven here, stated rather than implied: that the two
//! PRODUCTION call sites hold the permit across their exchange. That is a
//! call-site property (checks 74b/79b's stated limit), and it is covered by
//! the two gate cases at the tail of `llm_failure_metrics_tests.rs`, which
//! drive `wit_llm::Host::complete` against the mock provider and read the peak
//! concurrency out of the BACKEND. They live there rather than here because
//! `ollama_base_url()` is a `OnceLock`, so one test binary gets exactly one
//! mock provider and it must be shared.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use super::{
    acquire_from, resolve_max_in_flight, LocalLlmSlot, Ungated, DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT,
    GATE_OUTCOME_LABELS,
};

fn sem(n: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(n))
}

/// A cap of 1 must admit exactly one holder at a time.
///
/// Asserts on OBSERVED PEAK CONCURRENCY rather than on elapsed time: a timing
/// assertion would be a flake, and "the second task finished later" is also
/// true of a gate that does nothing on a loaded machine.
#[tokio::test]
async fn a_cap_of_one_admits_one_holder_at_a_time() {
    let permits = sem(1);
    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let permits = permits.clone();
        let live = live.clone();
        let peak = peak.clone();
        tasks.push(tokio::spawn(async move {
            let (slot, _waited) = acquire_from(Some(&permits), Duration::from_secs(5)).await;
            assert!(
                matches!(slot, LocalLlmSlot::Held(_)),
                "a 5 s wait against 8 short holders must not expire"
            );
            let now = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            live.fetch_sub(1, Ordering::SeqCst);
            drop(slot);
        }));
    }
    for t in tasks {
        t.await.expect("task");
    }
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "cap 1 must serialize; observed peak concurrency"
    );
}

/// THE CONTROL. The same eight tasks against a cap of 4 must overlap.
///
/// Without it, "peak == 1" is equally consistent with a harness that never
/// runs two tasks at once — which is the shape that lets a gate test pass over
/// a gate that does nothing.
#[tokio::test]
async fn the_control_a_wider_cap_really_does_overlap() {
    let permits = sem(4);
    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let permits = permits.clone();
        let live = live.clone();
        let peak = peak.clone();
        tasks.push(tokio::spawn(async move {
            let (slot, _waited) = acquire_from(Some(&permits), Duration::from_secs(5)).await;
            let now = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(40)).await;
            live.fetch_sub(1, Ordering::SeqCst);
            drop(slot);
        }));
    }
    for t in tasks {
        t.await.expect("task");
    }
    assert!(
        peak.load(Ordering::SeqCst) > 1,
        "cap 4 must admit more than one holder, else the serialization test above proves nothing"
    );
}

/// A wait that expires PROCEEDS. It must never refuse, and it must never park
/// the caller past its cap.
///
/// This is the property that makes the gate a Pareto change: the worst case it
/// can produce is the pre-gate behaviour plus a bounded wait.
#[tokio::test]
async fn an_expired_wait_proceeds_ungated_and_never_refuses() {
    let permits = sem(1);
    let held = permits
        .clone()
        .acquire_owned()
        .await
        .expect("the only permit");

    let (slot, waited) = acquire_from(Some(&permits), Duration::from_millis(50)).await;
    assert_eq!(
        matches!(slot, LocalLlmSlot::Ungated(Ungated::WaitExpired)),
        true,
        "a blocked acquire must degrade to ungated, not error"
    );
    assert!(
        waited >= Duration::from_millis(50),
        "the reported wait must be the real one: {waited:?}"
    );
    drop(held);
}

/// A cap of 0 is the DISABLED arm and must not wait at all.
#[tokio::test]
async fn a_disabled_gate_returns_immediately_and_says_so() {
    let (slot, waited) = acquire_from(None, Duration::from_secs(120)).await;
    assert!(matches!(slot, LocalLlmSlot::Ungated(Ungated::Disabled)));
    assert_eq!(slot.outcome_label(), "disabled");
    assert_eq!(waited, Duration::ZERO);
}

/// The permit is released on drop, so a serialized queue drains.
#[tokio::test]
async fn dropping_the_slot_releases_the_permit() {
    let permits = sem(1);
    let (first, _) = acquire_from(Some(&permits), Duration::from_millis(50)).await;
    assert!(matches!(first, LocalLlmSlot::Held(_)));
    // Still held → the next acquire must expire.
    let (blocked, _) = acquire_from(Some(&permits), Duration::from_millis(30)).await;
    assert!(matches!(
        blocked,
        LocalLlmSlot::Ungated(Ungated::WaitExpired)
    ));
    drop(first);
    let (after, _) = acquire_from(Some(&permits), Duration::from_millis(200)).await;
    assert!(
        matches!(after, LocalLlmSlot::Held(_)),
        "the permit must come back when the slot is dropped"
    );
}

/// A typo must fall back to the DEFAULT, never to 0 (which would silently
/// switch the control off) — the fail-in-the-reassuring-direction shape.
#[test]
fn an_unparseable_cap_falls_back_to_the_default_not_to_disabled() {
    assert_eq!(resolve_max_in_flight(None), DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT);
    assert_eq!(
        resolve_max_in_flight(Some("")),
        DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT
    );
    assert_eq!(
        resolve_max_in_flight(Some("   ")),
        DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT
    );
    assert_eq!(
        resolve_max_in_flight(Some("two")),
        DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT
    );
    assert_eq!(
        resolve_max_in_flight(Some("-1")),
        DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT
    );
    // An EXPLICIT zero is honoured — that is the documented off switch.
    assert_eq!(resolve_max_in_flight(Some("0")), 0);
    assert_eq!(resolve_max_in_flight(Some("4")), 4);
    assert_eq!(resolve_max_in_flight(Some(" 4 ")), 4);
}

/// Every label the gate can emit must be in the pre-seeded set, or the series
/// an operator reads is absent exactly when the gate first has something to
/// say. Absent is not zero.
#[tokio::test]
async fn every_emitted_label_is_pre_seeded() {
    let permits = sem(1);
    let (held, _) = acquire_from(Some(&permits), Duration::from_millis(50)).await;
    let (expired, _) = acquire_from(Some(&permits), Duration::from_millis(20)).await;
    let (disabled, _) = acquire_from(None, Duration::from_millis(20)).await;
    for slot in [&held, &expired, &disabled] {
        assert!(
            GATE_OUTCOME_LABELS.contains(&slot.outcome_label()),
            "emitted label {:?} is not in GATE_OUTCOME_LABELS {:?}",
            slot.outcome_label(),
            GATE_OUTCOME_LABELS
        );
    }
    assert_eq!(held.outcome_label(), "acquired");
    assert_eq!(expired.outcome_label(), "wait_expired");
    assert_eq!(disabled.outcome_label(), "disabled");
}
