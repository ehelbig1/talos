// Import the router from the controller crate (integration test crate).
use anyhow::Context;
use axum::http::header::HeaderValue;
use axum::http::HeaderMap;
use controller::dlp::DlpService;
use controller::module_executions::ModuleExecutionService;
use controller::webhooks::{CircuitBreaker, WebhookRouter};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

// Helper to create a minimal router for testing HMAC verification.
//
// Runs inside the test's Tokio runtime (`#[tokio::test]`): `WebhookRouter::new`
// spawns a background DLQ processor via `tokio::spawn`, which panics outside a
// runtime. Both the Postgres pool (`connect_lazy`) and the NATS client
// (`retry_on_initial_connect`) are lazy, so no live DB or NATS server is needed —
// the HMAC verification under test touches neither.
async fn test_router() -> anyhow::Result<WebhookRouter> {
    // Ensure SecretsManager can initialize without requiring external secrets.
    std::env::set_var("TALOS_MASTER_KEY", "a".repeat(64));
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://localhost/dummy")
        .expect("Failed to create lazy pool");

    let (event_sender, _) = tokio::sync::broadcast::channel(1);
    let (dlq_event_sender, _) = tokio::sync::broadcast::channel(1);
    let dlp_service = Arc::new(DlpService::from_env());
    let module_execution_service = Arc::new(ModuleExecutionService::new(pool.clone(), dlp_service));
    WebhookRouter::new(
        pool.clone(),
        Arc::new(controller::registry::ModuleRegistry::new(
            pool.clone(),
            None,
        )),
        Arc::new(
            controller::secrets::SecretsManager::new(pool.clone())
                .context("SecretsManager init")?,
        ),
        Arc::new(
            // Lazy NATS client: returns immediately, reconnects in the
            // background — no live server needed (see fn-level comment).
            async_nats::ConnectOptions::new()
                .retry_on_initial_connect()
                .connect("nats://localhost:4222")
                .await
                .context("nats client (lazy)")?,
        ),
        None,
        Arc::new(CircuitBreaker::new()),
        None,
        Some(module_execution_service),
        event_sender,
        dlq_event_sender,
        None,
        // RFC 0010 P3 (M4): no claim-based sealing handle in this HMAC unit test.
        None,
    )
}

#[tokio::test]
async fn verify_slack_hmac() {
    let secret = "test_secret";
    let body = b"{\"type\":\"url_verification\"}";
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    // Compute expected Slack signature
    let base = format!("v0:{}:", timestamp);
    let mut msg = base.into_bytes();
    msg.extend_from_slice(body);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&msg);
    let result = mac.finalize();
    let expected_hex = hex::encode(result.into_bytes());

    // Prepare headers
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-slack-signature",
        HeaderValue::from_str(&format!("v0={}", expected_hex)).unwrap(),
    );
    headers.insert(
        "x-slack-request-timestamp",
        HeaderValue::from_str(&timestamp).unwrap(),
    );

    let router = test_router().await.expect("router init");
    assert!(router.verify_hmac_signature(&headers, &body[..].into(), secret));
}
