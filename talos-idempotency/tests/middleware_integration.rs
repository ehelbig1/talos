//! Redis-backed integration tests for `idempotency_middleware` — the full
//! HTTP-level behavior, not just the `begin`/`complete`/`release` primitive
//! (which `redis_integration.rs` covers).
//!
//! These lock down the security-critical middleware properties that the
//! in-crate unit tests can only assert in their *passthrough* form (they use a
//! never-connect service, so they never reach the cache/replay path):
//!
//!   * faithful replay — a retried request returns the cached status + body +
//!     `idempotent-replayed: true`, and the handler does NOT run twice;
//!   * caller isolation — two DIFFERENT callers using the SAME key + body get
//!     INDEPENDENT executions (no cross-user cached-response leak);
//!   * Set-Cookie responses are NOT cached (a retry re-executes, so it can
//!     mint a fresh session cookie — and no live token sits in Redis);
//!   * 5xx responses are released (a retry re-executes rather than replaying
//!     a transient error or getting stuck `InFlight`);
//!   * key reuse with a different body → 422.
//!
//! Skipped (green) unless `TALOS_TEST_REDIS_URL` is set. Run locally against a
//! disposable Redis:
//!
//! ```bash
//! docker run -d --rm -p 16399:6379 redis:7-alpine
//! TALOS_TEST_REDIS_URL=redis://127.0.0.1:16399 \
//!   cargo test -p talos-idempotency --test middleware_integration
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::Extension;
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use talos_idempotency::{
    idempotency_middleware, IdempotencyService, IDEMPOTENCY_KEY_HEADER, IDEMPOTENT_REPLAYED_HEADER,
};
use tower::ServiceExt;

fn service() -> Option<Arc<IdempotencyService>> {
    let url = std::env::var("TALOS_TEST_REDIS_URL").ok()?;
    let client = redis::Client::open(url).expect("valid TALOS_TEST_REDIS_URL");
    Some(Arc::new(IdempotencyService::new(
        Arc::new(client),
        Duration::from_secs(3600),
    )))
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

/// Unique key per test so runs don't collide across the shared Redis.
fn unique_key() -> String {
    format!("mw-itest-{}", uuid::Uuid::new_v4())
}

/// 200 handler whose body encodes the execution count, so a replay (cached
/// body) is distinguishable from a fresh run (incremented count).
async fn counting_handler(Extension(counter): Extension<Arc<AtomicUsize>>) -> Response {
    let n = counter.fetch_add(1, Ordering::SeqCst);
    (StatusCode::OK, format!("exec-{n}")).into_response()
}

/// 200 handler that sets a session cookie — exercises the Set-Cookie
/// no-cache path.
async fn cookie_handler(Extension(counter): Extension<Arc<AtomicUsize>>) -> Response {
    let n = counter.fetch_add(1, Ordering::SeqCst);
    let mut resp = (StatusCode::OK, format!("cookie-{n}")).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        "talos_access_token=fresh; HttpOnly".parse().unwrap(),
    );
    resp
}

/// 500 handler — exercises the release-on-5xx path.
async fn error_handler(Extension(counter): Extension<Arc<AtomicUsize>>) -> Response {
    counter.fetch_add(1, Ordering::SeqCst);
    (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
}

fn app(service: Arc<IdempotencyService>, counter: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route("/exec", post(counting_handler))
        .route("/cookie", post(cookie_handler))
        .route("/error", post(error_handler))
        .layer(axum::middleware::from_fn(idempotency_middleware))
        .layer(Extension(Some(service)))
        .layer(Extension(counter))
}

async fn body_string(resp: Response) -> String {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn req(path: &str, key: &str, body: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::post(path).header(IDEMPOTENCY_KEY_HEADER, key);
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn replays_cached_response_without_rerunning_handler() {
    let svc = svc_or_skip!();
    let counter = Arc::new(AtomicUsize::new(0));
    let key = unique_key();

    // First call executes the handler.
    let r1 = app(svc.clone(), counter.clone())
        .oneshot(req("/exec", &key, "body-A", None))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    assert!(r1.headers().get(IDEMPOTENT_REPLAYED_HEADER).is_none());
    assert_eq!(body_string(r1).await, "exec-0");

    // Second identical call replays the cached response; handler does NOT run.
    let r2 = app(svc.clone(), counter.clone())
        .oneshot(req("/exec", &key, "body-A", None))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(
        r2.headers()
            .get(IDEMPOTENT_REPLAYED_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    assert_eq!(
        body_string(r2).await,
        "exec-0",
        "must replay the FIRST body"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "handler must have run exactly once across both calls"
    );
}

#[tokio::test]
async fn distinct_callers_do_not_share_cached_responses() {
    // SECURITY: the whole reason caller_scope exists. Two callers choosing the
    // same Idempotency-Key + body must get INDEPENDENT executions — caller B
    // must never replay caller A's cached response (a created secret, API key…).
    let svc = svc_or_skip!();
    let counter = Arc::new(AtomicUsize::new(0));
    let key = unique_key();

    let ra = app(svc.clone(), counter.clone())
        .oneshot(req("/exec", &key, "same-body", Some("Bearer AAA")))
        .await
        .unwrap();
    assert_eq!(body_string(ra).await, "exec-0");

    // Caller B: same key, same body, DIFFERENT credential.
    let rb = app(svc.clone(), counter.clone())
        .oneshot(req("/exec", &key, "same-body", Some("Bearer BBB")))
        .await
        .unwrap();
    assert!(
        rb.headers().get(IDEMPOTENT_REPLAYED_HEADER).is_none(),
        "caller B must NOT get a replayed response"
    );
    assert_eq!(
        body_string(rb).await,
        "exec-1",
        "caller B must execute fresh, not read caller A's cached body"
    );
    assert_eq!(counter.load(Ordering::SeqCst), 2, "both callers executed");
}

#[tokio::test]
async fn set_cookie_response_is_not_cached() {
    let svc = svc_or_skip!();
    let counter = Arc::new(AtomicUsize::new(0));
    let key = unique_key();

    let r1 = app(svc.clone(), counter.clone())
        .oneshot(req("/cookie", &key, "b", None))
        .await
        .unwrap();
    assert!(r1.headers().contains_key(header::SET_COOKIE));
    assert_eq!(body_string(r1).await, "cookie-0");

    // Retry: the Set-Cookie response was released, not cached, so the handler
    // re-runs (and could mint a fresh cookie) rather than replaying.
    let r2 = app(svc.clone(), counter.clone())
        .oneshot(req("/cookie", &key, "b", None))
        .await
        .unwrap();
    assert!(
        r2.headers().get(IDEMPOTENT_REPLAYED_HEADER).is_none(),
        "Set-Cookie responses must not be replayed"
    );
    assert_eq!(body_string(r2).await, "cookie-1");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn server_error_is_released_for_retry() {
    let svc = svc_or_skip!();
    let counter = Arc::new(AtomicUsize::new(0));
    let key = unique_key();

    let r1 = app(svc.clone(), counter.clone())
        .oneshot(req("/error", &key, "b", None))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // A 5xx must NOT be cached: the retry re-executes (not stuck InFlight, not
    // replaying the transient error).
    let r2 = app(svc.clone(), counter.clone())
        .oneshot(req("/error", &key, "b", None))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(r2.headers().get(IDEMPOTENT_REPLAYED_HEADER).is_none());
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "5xx must be released so the retry re-executes"
    );
}

#[tokio::test]
async fn same_key_different_body_is_rejected() {
    let svc = svc_or_skip!();
    let counter = Arc::new(AtomicUsize::new(0));
    let key = unique_key();

    let r1 = app(svc.clone(), counter.clone())
        .oneshot(req("/exec", &key, "body-1", None))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    // Same key, different body → 422 (key reuse with a changed request).
    let r2 = app(svc.clone(), counter.clone())
        .oneshot(req("/exec", &key, "body-2", None))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the mismatched retry must not execute the handler"
    );
}
