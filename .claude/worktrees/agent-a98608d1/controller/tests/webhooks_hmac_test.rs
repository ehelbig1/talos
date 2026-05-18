// Import the router from the controller crate (integration test crate).
use anyhow::Context;
use axum::http::header::HeaderValue;
use axum::http::HeaderMap;
use controller::webhooks::WebhookRouter;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Helper to create a minimal router for testing HMAC verification.
fn test_router() -> anyhow::Result<WebhookRouter> {
    // Use a dummy lazy pool (no real DB connection needed for HMAC tests)
    // Establish a Tokio runtime before creating a lazy connection pool, as sqlx
    // requires a runtime for its internal background tasks.
    // Ensure SecretsManager can initialize without requiring external secrets.
    std::env::set_var("TALOS_MASTER_KEY", "a".repeat(64));
    let rt = Runtime::new().expect("Failed to create Tokio runtime");
    let pool = rt.block_on(async {
        PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/dummy")
            .expect("Failed to create lazy pool")
    });

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
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async_nats::connect("nats://localhost:4222"))
                .unwrap(),
        ),
        None,
    )
}

#[test]
#[ignore] // Requires NATS to be running
fn verify_slack_hmac() {
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

    let router = test_router().expect("router init");
    assert!(router.verify_hmac_signature(&headers, &body[..].into(), secret));
}
