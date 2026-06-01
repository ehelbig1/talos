//! Redis-backed integration tests for the idempotency reservation primitive
//! (`begin` / `complete` / `release`). The atomic GET-and-claim is implemented
//! as a Redis Lua `EVAL`, so its real behavior — especially that exactly one
//! concurrent caller wins the reservation — can only be verified against a live
//! Redis, not the in-process unit tests.
//!
//! Skipped (green) unless `TALOS_TEST_REDIS_URL` is set, so CI without a Redis
//! stays green. Run locally against a disposable Redis:
//!
//! ```bash
//! docker run -d --rm -p 16399:6379 redis:7-alpine
//! TALOS_TEST_REDIS_URL=redis://127.0.0.1:16399 \
//!   cargo test -p talos-idempotency --test redis_integration
//! ```

use std::sync::Arc;
use std::time::Duration;
use talos_idempotency::{BeginOutcome, IdempotencyService};

fn service() -> Option<IdempotencyService> {
    let url = std::env::var("TALOS_TEST_REDIS_URL").ok()?;
    let client = redis::Client::open(url).expect("valid TALOS_TEST_REDIS_URL");
    Some(IdempotencyService::new(
        Arc::new(client),
        Duration::from_secs(3600),
    ))
}

/// Unique key per test so runs don't collide across the shared Redis.
fn unique_key() -> String {
    format!("itest-{}", uuid::Uuid::new_v4())
}

macro_rules! svc_or_skip {
    () => {
        match service() {
            Some(s) => s,
            None => {
                eprintln!("skipping: TALOS_TEST_REDIS_URL is not set");
                return;
            }
        }
    };
}

#[tokio::test]
async fn proceed_then_inflight_then_complete_then_hit() {
    let svc = svc_or_skip!();
    let key = unique_key();
    let hash = "hash-a";

    // First arrival claims the reservation.
    assert!(matches!(
        svc.begin(&key, hash).await.unwrap(),
        BeginOutcome::Proceed
    ));
    // A second caller (same key+hash, reservation still open) is told InFlight.
    assert!(matches!(
        svc.begin(&key, hash).await.unwrap(),
        BeginOutcome::InFlight
    ));
    // The winner records the response …
    assert!(svc
        .complete(&key, hash, 201, Some("{\"ok\":true}"), Some("application/json"))
        .await
        .unwrap());
    // … and now begin replays the cached response.
    match svc.begin(&key, hash).await.unwrap() {
        BeginOutcome::Hit(rec) => {
            assert_eq!(rec.status_code, 201);
            assert_eq!(rec.response_body.as_deref(), Some("{\"ok\":true}"));
            assert_eq!(rec.content_type.as_deref(), Some("application/json"));
        }
        other => panic!("expected Hit, got {other:?}"),
    }
}

#[tokio::test]
async fn mismatch_on_different_request_hash() {
    let svc = svc_or_skip!();
    let key = unique_key();

    assert!(matches!(
        svc.begin(&key, "hash-a").await.unwrap(),
        BeginOutcome::Proceed
    ));
    svc.complete(&key, "hash-a", 200, Some("body-a"), None)
        .await
        .unwrap();

    // Same key, DIFFERENT body hash → Mismatch (and never the cached body-a).
    assert!(matches!(
        svc.begin(&key, "hash-b").await.unwrap(),
        BeginOutcome::Mismatch
    ));
}

#[tokio::test]
async fn release_lets_a_retry_proceed_again() {
    let svc = svc_or_skip!();
    let key = unique_key();

    assert!(matches!(
        svc.begin(&key, "h").await.unwrap(),
        BeginOutcome::Proceed
    ));
    // Reservation open → a retry is InFlight.
    assert!(matches!(
        svc.begin(&key, "h").await.unwrap(),
        BeginOutcome::InFlight
    ));
    // Release (the 5xx path) frees the key so a retry can execute fresh.
    svc.release(&key, "h").await.unwrap();
    assert!(matches!(
        svc.begin(&key, "h").await.unwrap(),
        BeginOutcome::Proceed
    ));
}

#[tokio::test]
async fn release_does_not_clobber_a_completed_record() {
    let svc = svc_or_skip!();
    let key = unique_key();

    assert!(matches!(
        svc.begin(&key, "h").await.unwrap(),
        BeginOutcome::Proceed
    ));
    svc.complete(&key, "h", 200, Some("done"), None)
        .await
        .unwrap();
    // release only deletes an OPEN reservation, never a completed record —
    // a stray release after completion must leave the cached Hit intact.
    svc.release(&key, "h").await.unwrap();
    assert!(matches!(
        svc.begin(&key, "h").await.unwrap(),
        BeginOutcome::Hit(_)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_begin_yields_exactly_one_proceed() {
    let svc = Arc::new(svc_or_skip!());
    let key = unique_key();
    let hash = "h";

    // Fire many concurrent begins on the SAME key+hash. The atomic
    // GET-and-claim (single Redis EVAL) must hand Proceed to EXACTLY ONE
    // caller; everyone else gets InFlight. This is the TOCTOU-closing
    // property the whole reservation exists for — the racy check+store it
    // replaced would have handed Proceed to several.
    let n = 24;
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let svc = svc.clone();
        let key = key.clone();
        handles.push(tokio::spawn(
            async move { svc.begin(&key, hash).await.unwrap() },
        ));
    }

    let mut proceed = 0;
    let mut inflight = 0;
    for h in handles {
        match h.await.unwrap() {
            BeginOutcome::Proceed => proceed += 1,
            BeginOutcome::InFlight => inflight += 1,
            other => panic!("unexpected outcome under contention: {other:?}"),
        }
    }
    assert_eq!(proceed, 1, "exactly one concurrent caller must win the reservation");
    assert_eq!(inflight, n - 1, "all other concurrent callers must be InFlight");
}
