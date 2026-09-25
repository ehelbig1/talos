// ci-store: redis — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
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
use talos_idempotency::{BeginOutcome, IdempotencyService, WebhookDeduplication};

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
        .complete(
            &key,
            hash,
            201,
            Some("{\"ok\":true}"),
            Some("application/json")
        )
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
    assert_eq!(
        proceed, 1,
        "exactly one concurrent caller must win the reservation"
    );
    assert_eq!(
        inflight,
        n - 1,
        "all other concurrent callers must be InFlight"
    );
}

// ---------------------------------------------------------------------------
// Webhook deduplication (package CI, 2026-09-17)
//
// The retention window is passed per call because it is a property of the
// scheme that authenticated the delivery, not of the store: the GitHub HMAC
// signs the body alone, so it carries no freshness window and this claim is
// its ONLY replay defence. That the claim is really written with the window
// the caller asked for can only be checked against a live Redis — the TTL is
// server state, and a window silently truncated back to the old hour would
// restore the replay window package CI closed while every unit test stayed
// green.
// ---------------------------------------------------------------------------

fn dedup_or_skip() -> Option<(WebhookDeduplication, redis::Client)> {
    let url = std::env::var("TALOS_TEST_REDIS_URL").ok()?;
    let client = redis::Client::open(url).expect("valid TALOS_TEST_REDIS_URL");
    Some((WebhookDeduplication::new(Arc::new(client.clone())), client))
}

#[tokio::test]
async fn a_dedup_claim_is_held_for_the_window_the_caller_passed() {
    let Some((dedup, client)) = dedup_or_skip() else {
        eprintln!("skipping: TALOS_TEST_REDIS_URL is not set");
        return;
    };
    let trigger = uuid::Uuid::new_v4();
    let event = format!("sha256={}", uuid::Uuid::new_v4().simple());
    let window = Duration::from_secs(86_400);

    assert!(
        !dedup
            .is_duplicate(trigger, &event, window)
            .await
            .expect("first sighting"),
        "the first sighting of an event is not a duplicate"
    );
    assert!(
        dedup
            .is_duplicate(trigger, &event, window)
            .await
            .expect("second sighting"),
        "the same event again is a duplicate"
    );

    // The claim's TTL is the window the caller asked for, not the store's own
    // idea of one — read back from the server.
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let ttl: i64 = redis::cmd("TTL")
        .arg(format!("webhook:processed:{trigger}:{event}"))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(
        ttl > 86_000 && ttl <= 86_400,
        "claim TTL {ttl} is not the 24 h window that was passed"
    );

    // A shorter window on a DIFFERENT event is held for that shorter time —
    // the two horizons coexist in one store, which is the whole point of
    // passing it per call.
    let short_event = format!("v0={}", uuid::Uuid::new_v4().simple());
    assert!(!dedup
        .is_duplicate(trigger, &short_event, Duration::from_secs(3600))
        .await
        .unwrap());
    let short_ttl: i64 = redis::cmd("TTL")
        .arg(format!("webhook:processed:{trigger}:{short_event}"))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(
        short_ttl > 3400 && short_ttl <= 3600,
        "sibling claim TTL {short_ttl} is not the 1 h window that was passed"
    );

    // Releasing an abandoned claim lets the sender's redelivery through.
    dedup.release(trigger, &event).await.expect("release");
    assert!(
        !dedup
            .is_duplicate(trigger, &event, window)
            .await
            .expect("after release"),
        "a released claim must not suppress the redelivery"
    );
}

#[tokio::test]
async fn a_zero_dedup_window_is_refused_rather_than_failing_open() {
    let Some((dedup, _client)) = dedup_or_skip() else {
        eprintln!("skipping: TALOS_TEST_REDIS_URL is not set");
        return;
    };
    // `SET ... EX 0` is a Redis error, and the caller treats a dedup error as
    // "could not check". For the GitHub format that error is fail-closed (401),
    // so a zero window would take the integration off the air rather than
    // weaken it — but for every other format the router continues, which is a
    // replay check that silently never recorded anything. Refuse it here, at
    // the one place that can tell.
    let err = dedup
        .is_duplicate(uuid::Uuid::new_v4(), "e", Duration::from_secs(0))
        .await
        .expect_err("a zero window must be refused");
    assert!(
        err.to_string().contains("at least one second"),
        "unexpected error: {err}"
    );
}
