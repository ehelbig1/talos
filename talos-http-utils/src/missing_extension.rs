//! Detects a mounted route that extracts an axum `Extension` its router does
//! not provide.
//!
//! axum's `Extension<T>` extractor looks `T` up in the request's extensions,
//! and nothing checks at compile time that some layer put it there. A handler
//! mounted on a router without the matching `.layer(Extension(..))` compiles,
//! and every request to it is rejected before the handler body runs: status
//! 500, `text/plain`, body `Missing request extension: Extension of type
//! `<full Rust type path>` was not found. Perhaps you forgot to add it?
//! See `Router::layer`.`
//!
//! Package BZ (2026-09-16) measured that shape on two routes, `GET /metrics`
//! and `GET /graphql/schema`, both asking for `TalosSchema`, which only the
//! `/graphql` + `/ws` sub-router carries. Both answered it from the day they
//! were mounted, nothing counted or logged it, and the body named internal
//! types to any caller. Both routes were deleted; this layer is the runtime
//! half of the guard against the next one (the other half is the route crawl,
//! `scripts/check-route-extensions.py`, which reads this module's counter).
//!
//! On a rejection this layer logs an ERROR naming the method and the matched
//! route template, increments `talos_http_missing_extension_total`, and
//! replaces the body with a generic one. Only a response that can be the
//! rejection is read: status 500, `text/plain`, and a body whose exact size is
//! known and small. Every other response passes through untouched and unread.

use axum::{
    body::{Body, HttpBody},
    extract::{MatchedPath, Request},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// The start of axum's `MissingExtension` rejection body (axum 0.8).
/// `rejection_body_prefix_is_axums` pins this against a real rejection, so an
/// axum upgrade that rewords it fails a test instead of silencing the layer.
pub const MISSING_EXTENSION_BODY_PREFIX: &str = "Missing request extension";

/// Largest body this layer reads. axum's rejection body is ~250 bytes; the
/// limit only bounds the read of an unrelated small plain-text 500.
pub const MAX_INSPECTED_BODY_BYTES: u64 = 4096;

/// The body sent in place of the rejection text.
pub const REPLACEMENT_BODY: &str = "Internal Server Error";

/// Whether `response` can be axum's missing-extension rejection, decided from
/// the status, the content type and the body's exact size alone.
#[must_use]
pub fn may_be_missing_extension_rejection(response: &Response) -> bool {
    if response.status() != StatusCode::INTERNAL_SERVER_ERROR {
        return false;
    }
    let plain_text = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/plain"));
    let small_and_exact = response
        .body()
        .size_hint()
        .exact()
        .is_some_and(|n| n <= MAX_INSPECTED_BODY_BYTES);
    plain_text && small_and_exact
}

/// Axum middleware: add with `Router::layer` outside every route so the
/// matched route template is available.
pub async fn missing_extension_guard(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned());

    let response = next.run(request).await;
    if !may_be_missing_extension_rejection(&response) {
        return response;
    }

    let (parts, body) = response.into_parts();
    // The size is exact and below the limit, so this reads the whole body.
    let Ok(bytes) = axum::body::to_bytes(body, MAX_INSPECTED_BODY_BYTES as usize).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, REPLACEMENT_BODY).into_response();
    };
    if !bytes.starts_with(MISSING_EXTENSION_BODY_PREFIX.as_bytes()) {
        return Response::from_parts(parts, Body::from(bytes));
    }

    if let Some(metrics) = talos_metrics::global() {
        metrics.http_missing_extension_total.inc();
    }
    tracing::error!(
        event_kind = "route_missing_extension",
        method = %method,
        route = route.as_deref().unwrap_or("<unmatched>"),
        rejection = %String::from_utf8_lossy(&bytes),
        "a mounted route extracts an axum Extension its router does not provide; \
         every request to it fails before the handler runs (response body replaced)"
    );
    (StatusCode::INTERNAL_SERVER_ERROR, REPLACEMENT_BODY).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware::from_fn, routing::get, Extension, Router};
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, SubscriberExt};

    /// The counter is process-global; tests that read it run one at a time.
    static COUNTER_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone)]
    struct NeverLayered;

    async fn needs_missing(Extension(_): Extension<NeverLayered>) -> &'static str {
        "reached"
    }

    fn metrics() -> &'static Arc<talos_metrics::TalosMetrics> {
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        talos_metrics::global().expect("global installed")
    }

    fn app() -> Router {
        Router::new()
            .route("/needs/{id}", get(needs_missing))
            .route(
                "/plain-500",
                get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "database unavailable") }),
            )
            .route(
                "/ok-with-marker-text",
                get(|| async { "Missing request extension: this is a 200, not a rejection" }),
            )
            .merge(
                Router::new()
                    .route("/layered", get(needs_missing))
                    .layer(Extension(NeverLayered)),
            )
            .layer(from_fn(missing_extension_guard))
    }

    async fn call(router: Router, path: &str) -> (StatusCode, String) {
        let res = router
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[derive(Default, Clone)]
    struct Captured(Arc<Mutex<Vec<(String, String)>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
        fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
            struct V<'a>(&'a mut Vec<(String, String)>);
            impl Visit for V<'_> {
                fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
                    self.0.push((f.name().to_string(), format!("{v:?}")));
                }
                fn record_str(&mut self, f: &Field, v: &str) {
                    self.0.push((f.name().to_string(), v.to_string()));
                }
            }
            if *event.metadata().level() == tracing::Level::ERROR {
                event.record(&mut V(&mut self.0.lock().unwrap()));
            }
        }
    }

    #[tokio::test]
    async fn rejection_body_prefix_is_axums() {
        // No guard: this is axum's own rendering, the thing the layer matches.
        let bare = Router::new().route("/needs/{id}", get(needs_missing));
        let (status, body) = call(bare, "/needs/1").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            body.starts_with(MISSING_EXTENSION_BODY_PREFIX),
            "axum now renders: {body}"
        );
    }

    #[tokio::test]
    async fn a_missing_extension_is_counted_logged_and_its_body_replaced() {
        let _serial = COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let m = metrics();
        let before = m.http_missing_extension_total.get();

        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        let (status, body) = call(app(), "/needs/42").await;
        drop(_guard);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, REPLACEMENT_BODY);
        assert!(!body.contains("NeverLayered"), "a type name leaked: {body}");
        assert_eq!(m.http_missing_extension_total.get() - before, 1.0);

        let fields = captured.0.lock().unwrap().clone();
        let field = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(
            field("event_kind").as_deref(),
            Some("route_missing_extension")
        );
        assert_eq!(
            field("route").as_deref(),
            Some("/needs/{id}"),
            "the TEMPLATE, never the raw path"
        );
        assert_eq!(field("method").as_deref(), Some("GET"));
        assert!(field("rejection").is_some_and(|r| r.contains("NeverLayered")));
    }

    #[tokio::test]
    async fn other_responses_pass_through_and_count_nothing() {
        let _serial = COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let m = metrics();
        let before = m.http_missing_extension_total.get();

        // A different plain-text 500 keeps its body.
        assert_eq!(
            call(app(), "/plain-500").await,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database unavailable".to_string()
            )
        );
        // The same text on a 200 is not a rejection.
        let (status, body) = call(app(), "/ok-with-marker-text").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with(MISSING_EXTENSION_BODY_PREFIX));
        // The extension present: the handler runs.
        assert_eq!(
            call(app(), "/layered").await,
            (StatusCode::OK, "reached".to_string())
        );

        assert_eq!(m.http_missing_extension_total.get(), before);
    }

    #[test]
    fn only_a_small_exact_plain_text_500_is_read() {
        let plain = |status: StatusCode, body: Body| {
            let mut r = Response::new(body);
            *r.status_mut() = status;
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".parse().unwrap(),
            );
            r
        };
        assert!(may_be_missing_extension_rejection(&plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            Body::from("x")
        )));
        assert!(!may_be_missing_extension_rejection(&plain(
            StatusCode::BAD_GATEWAY,
            Body::from("x")
        )));
        let big = "x".repeat(MAX_INSPECTED_BODY_BYTES as usize + 1);
        assert!(!may_be_missing_extension_rejection(&plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            Body::from(big)
        )));
        // A stream of unknown length is never buffered.
        let stream = Body::from_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
            axum::body::Bytes::from_static(b"x"),
        )]));
        assert!(!may_be_missing_extension_rejection(&plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            stream
        )));
        let mut json = plain(StatusCode::INTERNAL_SERVER_ERROR, Body::from("x"));
        json.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(!may_be_missing_extension_rejection(&json));
    }
}
