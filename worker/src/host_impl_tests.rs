use std::collections::HashMap;
use crate::context::TalosContext;
use crate::wit_inspector::CapabilityWorld;
use crate::bindings::talos::core::http::{self as wit_http, Host};
use crate::bindings::talos::core::crypto::{self as wit_crypto, Host as _};

#[tokio::test]
async fn test_http_fetch_forbidden_world() {
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec!["*".to_string()],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://example.com".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };

    let result = ctx.fetch(req).await;
    assert!(matches!(result, Err(wit_http::Error::Forbiddenhost)));
}

#[tokio::test]
async fn test_http_fetch_allowlist_enforcement() {
    let mut ctx = TalosContext::new(
        CapabilityWorld::Http,
        vec!["example.com".to_string()],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    // Allowed host
    let req_ok = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://example.com/foo".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };

    // We don't actually want to make a real network call in unit tests if possible,
    // but the current implementation of `fetch` calls `reqwest::Client::send().await`.
    // For this unit test, we can at least verify it GETS PAST the allowlist check
    // by checking if it returns Forbiddenhost or something else (like Networkerror if DNS fails).
    let result_ok = ctx.fetch(req_ok).await;
    // If it's not Forbiddenhost, it passed the allowlist check.
    assert!(!matches!(result_ok, Err(wit_http::Error::Forbiddenhost)));

    // Forbidden host
    let req_bad = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://google.com".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result_bad = ctx.fetch(req_bad).await;
    assert!(matches!(result_bad, Err(wit_http::Error::Forbiddenhost)));
}

#[tokio::test]
async fn test_http_ssrf_protection() {
    let mut ctx = TalosContext::new(
        CapabilityWorld::Http,
        vec!["*".to_string()], // Wildcard allowlist
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    let private_ips = [
        "http://127.0.0.1",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://169.254.169.254",
        "http://[::1]",
        "http://[fe80::1]",
    ];

    for url in private_ips {
        let req = wit_http::Request {
            method: wit_http::Method::Get,
            url: url.to_string(),
            headers: vec![],
            body: vec![],
            timeout_ms: None,
        };
        let result = ctx.fetch(req).await;
        assert!(
            matches!(result, Err(wit_http::Error::Forbiddenhost)),
            "URL {} should be blocked by SSRF protection", url
        );
    }
}

#[tokio::test]
async fn test_crypto_hash_limits() {
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    // 101 MB (limit is 100 MB)
    let huge_data = vec![0u8; 101 * 1024 * 1024];
    let result = <TalosContext as wit_crypto::Host>::hash(&mut ctx, wit_crypto::HashAlgorithm::Sha256, huge_data).await;
    assert!(result.is_empty(), "Hash of oversized data should return empty vector");
}

#[tokio::test]
async fn test_crypto_random_bytes_limits() {
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    // 1.1 MB (limit is 1 MB)
    let result = <TalosContext as wit_crypto::Host>::random_bytes(&mut ctx, 1_100_000).await;
    assert!(result.is_empty(), "Random bytes request > 1MB should return empty vector");

    let ok_result = <TalosContext as wit_crypto::Host>::random_bytes(&mut ctx, 100).await;
    assert_eq!(ok_result.len(), 100);
}

#[tokio::test]
async fn test_json_path_query() {
    use crate::bindings::talos::core::json::{self as wit_json, Host as _};
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    let json = r#"{"user": {"email": "test@example.com", "tags": ["a", "b"]}, "items": [1, 2, 3]}"#;

    // Simple path
    let res = <TalosContext as wit_json::Host>::query(&mut ctx, json.to_string(), "user.email".to_string()).await.unwrap();
    assert_eq!(res, "\"test@example.com\"");

    // Array index
    let res = <TalosContext as wit_json::Host>::query(&mut ctx, json.to_string(), "items[1]".to_string()).await.unwrap();
    assert_eq!(res, "2");

    // Nested array
    let res = <TalosContext as wit_json::Host>::query(&mut ctx, json.to_string(), "user.tags[0]".to_string()).await.unwrap();
    assert_eq!(res, "\"a\"");

    // Invalid path
    let res = <TalosContext as wit_json::Host>::query(&mut ctx, json.to_string(), "nonexistent".to_string()).await;
    assert!(matches!(res, Err(wit_json::Error::Invalidpath)));
}

#[tokio::test]
async fn test_logging_redaction() {
    use crate::bindings::talos::core::logging::{self as wit_logging, Host as _};
    let mut secrets = HashMap::new();
    secrets.insert("API_KEY".to_string(), "secret-token-123".to_string());

    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        secrets,
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    // We can't easily capture tracing output in a unit test without complex setup,
    // but we can verify the redaction logic doesn't crash and the NATS publish
    // (if it were configured) would use the redacted message.
    // For now, just ensure it runs.
    <TalosContext as wit_logging::Host>::log(&mut ctx, wit_logging::Level::Info, "Key is secret-token-123".to_string()).await;
}

#[tokio::test]
async fn test_datetime_operations() {
    use crate::bindings::talos::core::datetime::{self as wit_datetime, Host as _};
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    let now = <TalosContext as wit_datetime::Host>::now_unix(&mut ctx).await;
    assert!(now > 1700000000); // Sometime in the recent past

    let iso = "2024-01-01T00:00:00Z";
    let ts = <TalosContext as wit_datetime::Host>::parse(&mut ctx, iso.to_string(), None).await.unwrap();
    assert_eq!(ts, 1704067200);

    let formatted = <TalosContext as wit_datetime::Host>::format(&mut ctx, ts, "%Y-%m-%d".to_string()).await.unwrap();
    assert_eq!(formatted, "2024-01-01");
}
