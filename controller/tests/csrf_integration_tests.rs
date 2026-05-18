use axum::{
    body::Body as AxumBody,
    http::{header, Method, Request, StatusCode},
    middleware::from_fn,
    routing::{get, post},
    Router,
};
use controller::csrf::*;
use tower::ServiceExt;
use tower_cookies::CookieManagerLayer;

async fn setup_app() -> Router {
    Router::new()
        .route("/", get(|| async { "GET OK" }))
        .route("/mutate", post(|| async { "POST OK" }))
        .route("/webhooks/test", post(|| async { "WEBHOOK OK" }))
        .route("/health", get(|| async { "HEALTH OK" }))
        .route(
            "/graphql",
            post(|_body: String| async move { "GRAPHQL OK" }),
        )
        .layer(from_fn(csrf_protection))
        .layer(CookieManagerLayer::new())
}

#[tokio::test]
async fn test_csrf_integration_get_sets_cookie() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.contains("talos_csrf_token="));
}

#[tokio::test]
async fn test_csrf_integration_post_no_token_fails() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mutate")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_csrf_integration_post_with_valid_token_succeeds() {
    let token = "test_token_12345678901234567890123456789012";
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mutate")
                .header(header::COOKIE, format!("talos_csrf_token={}", token))
                .header("X-CSRF-Token", token)
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_csrf_integration_webhook_bypass() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/test")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_csrf_integration_graphql_introspection_requires_danger_flag() {
    // In dev mode, x-dev-bypass header allows introspection queries without CSRF
    std::env::set_var("RUST_ENV", "development");
    std::env::remove_var("ALLOW_DEV_UNSAFE_CSRF_BYPASS");

    let app = Router::new()
        .route("/graphql", post(|| async { "GRAPHQL OK" }))
        .layer(from_fn(csrf_protection_graphql))
        .layer(CookieManagerLayer::new());

    let introspection_query = r#"{"query": "{ __schema { types { name } } }"}"#;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/graphql")
                .header("x-dev-bypass", "true")
                .body(AxumBody::from(introspection_query))
                .unwrap(),
        )
        .await
        .unwrap();

    // x-dev-bypass allows introspection in dev mode
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_csrf_integration_graphql_introspection_bypass_with_danger_flag() {
    // With ALLOW_DEV_UNSAFE_CSRF_BYPASS=true, introspection bypasses CSRF in dev mode
    std::env::set_var("RUST_ENV", "development");
    std::env::set_var("ALLOW_DEV_UNSAFE_CSRF_BYPASS", "true");

    let app = Router::new()
        .route("/graphql", post(|| async { "GRAPHQL OK" }))
        .layer(from_fn(csrf_protection_graphql))
        .layer(CookieManagerLayer::new());

    let introspection_query = r#"{"query": "{ __schema { types { name } } }"}"#;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/graphql")
                .header("x-dev-bypass", "true")
                .body(AxumBody::from(introspection_query))
                .unwrap(),
        )
        .await
        .unwrap();

    // In dev mode with x-dev-bypass header, introspection bypasses CSRF
    assert_eq!(response.status(), StatusCode::OK);

    // Clean up
    std::env::remove_var("ALLOW_DEV_UNSAFE_CSRF_BYPASS");
}

// ---------------------------------------------------------------------------
// Dev bypass header without DANGER flag should NOT bypass CSRF
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_csrf_dev_bypass_header_alone_does_not_work() {
    // Ensure neither bypass var is set — explicitly clear both so this test
    // is not affected by ALLOW_DEV_UNSAFE_CSRF_BYPASS being left set by a
    // concurrently-running sibling test (that env var causes allow_dev_bypass=true
    // which bypasses CSRF for all requests, not just introspection).
    std::env::set_var("RUST_ENV", "development");
    std::env::remove_var("ALLOW_DEV_UNSAFE_CSRF_BYPASS");
    std::env::remove_var("DANGER_DISABLE_CSRF_FOR_GRAPHQL_INTROSPECTION");

    let app = Router::new()
        .route("/graphql", post(|| async { "GRAPHQL OK" }))
        .layer(from_fn(csrf_protection_graphql))
        .layer(CookieManagerLayer::new());

    // Send a non-introspection mutation with only x-dev-bypass header
    let mutation = r#"{"query": "mutation { doSomething }"}"#;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/graphql")
                .header("x-dev-bypass", "true")
                .body(AxumBody::from(mutation))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "x-dev-bypass alone (without DANGER env var) should NOT bypass CSRF for mutations"
    );
}

// ---------------------------------------------------------------------------
// Constant-time comparison: verify matching tokens succeed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_csrf_constant_time_comparison_with_matching_tokens() {
    let token = "secure_csrf_token_at_least_32_characters_long";
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mutate")
                .header(header::COOKIE, format!("talos_csrf_token={}", token))
                .header("X-CSRF-Token", token)
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "matching cookie and header tokens should pass CSRF check"
    );
}

#[tokio::test]
async fn test_csrf_mismatched_tokens_are_rejected() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mutate")
                .header(
                    header::COOKIE,
                    "talos_csrf_token=cookie_token_value_32chars_long",
                )
                .header("X-CSRF-Token", "different_header_token_32chars_long")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "mismatched tokens should be rejected"
    );
}

#[tokio::test]
async fn test_csrf_missing_header_token_is_rejected() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mutate")
                .header(header::COOKIE, "talos_csrf_token=some_token_value_here")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "missing X-CSRF-Token header should be rejected"
    );
}

#[tokio::test]
async fn test_csrf_missing_cookie_is_rejected() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mutate")
                .header("X-CSRF-Token", "some_token_value")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "missing cookie should be rejected"
    );
}
