use controller::webhooks::WebhookRouter;
use axum::http::{HeaderMap, HeaderValue};
use axum::body::Bytes;
use std::sync::Arc;
use sqlx::postgres::PgPoolOptions;

#[test]
fn test_hmac_verification_various_providers() {
    // We don't need a real DB for pure logic check of verify_hmac_signature
    // but the constructor requires it. Use a lazy pool.
    std::env::set_var("TALOS_MASTER_KEY", "00".repeat(32));
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/dummy")
        .unwrap();

    let router = WebhookRouter::new_for_test(pool);
    let secret = "test-secret";
    let body = Bytes::from("{\"hello\":\"world\"}");

    // 1. Generic X-Signature
    let mut headers = HeaderMap::new();
    let generic_sig = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(&body);
        hex::encode(mac.finalize().into_bytes())
    };
    headers.insert("x-signature", HeaderValue::from_str(&generic_sig).unwrap());
    assert!(router.verify_hmac_signature(&headers, &body, secret), "Generic signature should pass");

    // 2. GitHub X-Hub-Signature-256
    let mut github_headers = HeaderMap::new();
    github_headers.insert("x-hub-signature-256", HeaderValue::from_str(&format!("sha256={}", generic_sig)).unwrap());
    assert!(router.verify_hmac_signature(&github_headers, &body, secret), "GitHub signature should pass");

    // 3. Slack (needs timestamp)
    let mut slack_headers = HeaderMap::new();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let slack_sig = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let basestring = format!("v0:{}:", ts);
        let mut full_message = basestring.into_bytes();
        full_message.extend_from_slice(&body);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(&full_message);
        hex::encode(mac.finalize().into_bytes())
    };

    slack_headers.insert("x-slack-signature", HeaderValue::from_str(&format!("v0={}", slack_sig)).unwrap());
    slack_headers.insert("x-slack-request-timestamp", HeaderValue::from_str(&ts).unwrap());
    assert!(router.verify_hmac_signature(&slack_headers, &body, secret), "Slack signature should pass");

    // 4. Invalid signature
    let mut bad_headers = HeaderMap::new();
    bad_headers.insert("x-signature", HeaderValue::from_static("wrong"));
    assert!(!router.verify_hmac_signature(&bad_headers, &body, secret), "Bad signature should fail");
}
