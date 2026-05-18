//! Request ID middleware for distributed tracing and audit logging.
//!
//! This module provides a middleware that:
//! - Generates a unique request ID for each incoming request
//! - Propagates existing request IDs from upstream services (via X-Request-ID header)
//! - Adds the request ID as a response header for client correlation
//! - Makes the request ID available for logging and tracing

use axum::{
    body::Body,
    http::{header, Request, Response},
    middleware::Next,
};

/// Default header name for request ID propagation
const REQUEST_ID_HEADER: &str = "x-request-id";

/// MCP-1017 (2026-05-15): cap on upstream-supplied request IDs.
/// Real-world request ID formats fit comfortably under this — UUID
/// (36 chars), AWS X-Ray (35), W3C traceparent (55), datadog tags
/// (~64). 128 covers proxy-chain concatenations (e.g.
/// `parent-id;child-id`) while bounding log/header memory cost.
const MAX_REQUEST_ID_LEN: usize = 128;

/// Generate a new unique request ID (UUID v4)
fn generate_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// MCP-1017: validate an upstream-supplied request ID against a
/// conservative shape — length cap and charset (alphanumeric +
/// `-_:.`). Returns the input unchanged when sane, otherwise None
/// so the caller falls back to a fresh UUID. Without this,
/// `X-Request-ID: "<64KB of '\n'>"` would land verbatim in tracing
/// spans (memory + log aggregation cost), echo back as a response
/// header, and bypass the per-span field discipline. A client
/// can't actually inject log structure here (tracing records the
/// value as ONE opaque span field, not interpolated into a log
/// line) but operator dashboards / log forwarders that flatten
/// spans into text DO render control chars verbatim — keep them
/// out at the boundary. Charset chosen as the intersection of
/// every common request ID format: UUID hyphens, W3C dashes,
/// Datadog colons + dots.
fn validate_upstream_request_id(raw: &str) -> Option<&str> {
    if raw.is_empty() || raw.len() > MAX_REQUEST_ID_LEN {
        return None;
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
    {
        return None;
    }
    Some(raw)
}

/// Middleware that handles request ID generation and propagation.
///
/// If the incoming request has an X-Request-ID header AND it passes
/// `validate_upstream_request_id`, it is preserved. Otherwise, a
/// new UUID v4 is generated.
/// The request ID is added as a response header for client correlation.
pub async fn request_id_middleware(request: Request<Body>, next: Next) -> Response<Body> {
    // Check for existing request ID from upstream
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(validate_upstream_request_id)
        .map(|s| s.to_string())
        .unwrap_or_else(generate_request_id);

    // Add request ID to the current tracing span
    tracing::Span::current().record("request_id", &request_id);

    // Continue with the request
    let mut response = next.run(request).await;

    // Add request ID to response headers for client correlation
    if let Ok(value) = header::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }

    response
}

// MCP-1035: `extract_request_id` (raw `to_str` with no MCP-1017
// validation) and `RequestId(pub String)` (public field — any caller
// could wrap an unsanitised header value and bypass the cap) were
// unused workspace-wide. Removed to eliminate the drift hazard. The
// canonical entry-point is `request_id_middleware`, which applies
// `validate_upstream_request_id` and is the only path that reads
// `X-Request-ID` from the request. Same drift class as MCP-1019.

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, middleware, response::Response, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_request_id_generated_when_missing() {
        let app = Router::new()
            .route("/", axum::routing::get(|| async { "OK" }))
            .layer(middleware::from_fn(request_id_middleware));

        let response: Response<Body> = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Should have generated a request ID
        let request_id = response.headers().get(REQUEST_ID_HEADER);
        assert!(request_id.is_some());

        // Should be a valid UUID
        let id_str = request_id.unwrap().to_str().unwrap();
        assert!(uuid::Uuid::parse_str(id_str).is_ok());
    }

    #[tokio::test]
    async fn test_request_id_preserved_when_provided() {
        let existing_id = "test-request-id-12345";

        let app = Router::new()
            .route("/", axum::routing::get(|| async { "OK" }))
            .layer(middleware::from_fn(request_id_middleware));

        let response: Response<Body> = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, existing_id)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should preserve the existing request ID
        let request_id = response.headers().get(REQUEST_ID_HEADER).unwrap();
        assert_eq!(request_id.to_str().unwrap(), existing_id);
    }

    // ── MCP-1017: upstream request ID validation ────────────────────

    #[test]
    fn validate_accepts_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(validate_upstream_request_id(uuid), Some(uuid));
    }

    #[test]
    fn validate_accepts_w3c_traceparent_id() {
        let id = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(validate_upstream_request_id(id), Some(id));
    }

    #[test]
    fn validate_accepts_datadog_style() {
        let id = "service:trace.id:12345.67";
        assert_eq!(validate_upstream_request_id(id), Some(id));
    }

    #[test]
    fn validate_rejects_empty() {
        assert_eq!(validate_upstream_request_id(""), None);
    }

    #[test]
    fn validate_rejects_oversized() {
        let oversized = "a".repeat(MAX_REQUEST_ID_LEN + 1);
        assert_eq!(validate_upstream_request_id(&oversized), None);
    }

    #[test]
    fn validate_rejects_newline_injection() {
        // log-forging shape — a control char that a flattening forwarder
        // would render verbatim.
        assert_eq!(validate_upstream_request_id("foo\nbar"), None);
    }

    #[test]
    fn validate_rejects_whitespace() {
        assert_eq!(validate_upstream_request_id("foo bar"), None);
    }

    #[test]
    fn validate_rejects_non_ascii() {
        assert_eq!(validate_upstream_request_id("café"), None);
    }

    #[test]
    fn validate_rejects_slash() {
        // path-traversal shape; not a real risk for request_id usage
        // but excluded by the conservative charset.
        assert_eq!(validate_upstream_request_id("../foo"), None);
    }

    #[test]
    fn validate_accepts_max_length() {
        let exactly_max = "a".repeat(MAX_REQUEST_ID_LEN);
        assert_eq!(
            validate_upstream_request_id(&exactly_max),
            Some(exactly_max.as_str())
        );
    }

    #[tokio::test]
    async fn upstream_invalid_request_id_is_replaced_with_uuid() {
        let app = Router::new()
            .route("/", axum::routing::get(|| async { "OK" }))
            .layer(middleware::from_fn(request_id_middleware));

        // Slash + space are visible-ASCII so http::HeaderValue accepts
        // them, but the upstream validator should reject and fall
        // back to a fresh UUID. (Control chars like '\n' are
        // already blocked at the http::HeaderValue boundary before
        // they reach our middleware.)
        let response: Response<Body> = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, "evil / shape")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let returned = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_ne!(
            returned, "evil / shape",
            "invalid upstream id must be replaced with a fresh UUID"
        );
        assert!(
            uuid::Uuid::parse_str(returned).is_ok(),
            "fallback must be a UUID, got: {returned}"
        );
    }

    #[tokio::test]
    async fn upstream_oversized_request_id_is_replaced_with_uuid() {
        let app = Router::new()
            .route("/", axum::routing::get(|| async { "OK" }))
            .layer(middleware::from_fn(request_id_middleware));

        let oversized = "a".repeat(MAX_REQUEST_ID_LEN + 1);
        let response: Response<Body> = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, &oversized)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let returned = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            returned.len() <= MAX_REQUEST_ID_LEN,
            "oversized id must not survive: {returned}"
        );
        assert!(
            uuid::Uuid::parse_str(returned).is_ok(),
            "fallback must be a UUID, got: {returned}"
        );
    }
}
