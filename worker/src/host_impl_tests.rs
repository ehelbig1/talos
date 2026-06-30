use crate::bindings::talos::core::crypto::{self as wit_crypto};
use crate::bindings::talos::core::http::{self as wit_http, Host};
use crate::context::TalosContext;
use crate::wit_inspector::CapabilityWorld;
use std::collections::HashMap;
use talos_workflow_job_protocol::LlmTier;

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
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

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
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

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
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

    // Use https:// so each request passes the HTTPS-only scheme gate and is
    // rejected specifically by the SSRF private-IP-literal gate (Forbiddenhost).
    // With http:// the scheme gate would short-circuit to Invalidurl first,
    // which would not exercise the SSRF protection this test is asserting.
    let private_ips = [
        "https://127.0.0.1",
        "https://192.168.1.1",
        "https://10.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://[fe80::1]",
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
            "URL {} should be blocked by SSRF protection",
            url
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
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

    // 101 MB (limit is 100 MB)
    let huge_data = vec![0u8; 101 * 1024 * 1024];
    let result = <TalosContext as wit_crypto::Host>::hash(
        &mut ctx,
        wit_crypto::HashAlgorithm::Sha256,
        huge_data,
    )
    .await;
    assert!(
        result.is_empty(),
        "Hash of oversized data should return empty vector"
    );
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
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

    // 1.1 MB (limit is 1 MB)
    let result = <TalosContext as wit_crypto::Host>::random_bytes(&mut ctx, 1_100_000).await;
    assert!(
        result.is_empty(),
        "Random bytes request > 1MB should return empty vector"
    );

    let ok_result = <TalosContext as wit_crypto::Host>::random_bytes(&mut ctx, 100).await;
    assert_eq!(ok_result.len(), 100);
}

#[tokio::test]
async fn test_json_path_query() {
    use crate::bindings::talos::core::json::{self as wit_json};
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

    let json = r#"{"user": {"email": "test@example.com", "tags": ["a", "b"]}, "items": [1, 2, 3]}"#;

    // Simple path
    let res = <TalosContext as wit_json::Host>::query(
        &mut ctx,
        json.to_string(),
        "user.email".to_string(),
    )
    .await
    .unwrap();
    assert_eq!(res, "\"test@example.com\"");

    // Array index
    let res =
        <TalosContext as wit_json::Host>::query(&mut ctx, json.to_string(), "items[1]".to_string())
            .await
            .unwrap();
    assert_eq!(res, "2");

    // Nested array
    let res = <TalosContext as wit_json::Host>::query(
        &mut ctx,
        json.to_string(),
        "user.tags[0]".to_string(),
    )
    .await
    .unwrap();
    assert_eq!(res, "\"a\"");

    // Invalid path
    let res = <TalosContext as wit_json::Host>::query(
        &mut ctx,
        json.to_string(),
        "nonexistent".to_string(),
    )
    .await;
    assert!(matches!(res, Err(wit_json::Error::Invalidpath)));
}

#[tokio::test]
async fn test_logging_redaction() {
    use crate::bindings::talos::core::logging::{self as wit_logging};
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
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

    // We can't easily capture tracing output in a unit test without complex setup,
    // but we can verify the redaction logic doesn't crash and the NATS publish
    // (if it were configured) would use the redacted message.
    // For now, just ensure it runs.
    <TalosContext as wit_logging::Host>::log(
        &mut ctx,
        wit_logging::Level::Info,
        "Key is secret-token-123".to_string(),
    )
    .await;
}

#[tokio::test]
async fn test_datetime_operations() {
    use crate::bindings::talos::core::datetime::{self as wit_datetime};
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

    let now = <TalosContext as wit_datetime::Host>::now_unix(&mut ctx).await;
    assert!(now > 1700000000); // Sometime in the recent past

    let iso = "2024-01-01T00:00:00Z";
    let ts = <TalosContext as wit_datetime::Host>::parse(&mut ctx, iso.to_string(), None)
        .await
        .unwrap();
    assert_eq!(ts, 1704067200);

    let formatted =
        <TalosContext as wit_datetime::Host>::format(&mut ctx, ts, "%Y-%m-%d".to_string())
            .await
            .unwrap();
    assert_eq!(formatted, "2024-01-01");
}

/// Tiny single-shot loopback HTTP server (no external dep). Binds
/// `127.0.0.1:0`, accepts ONE connection, reads the raw request bytes,
/// then replies `200 OK` with a `{}` body. Returns `(bound_port,
/// JoinHandle<captured request String>)` so a test can connect then await
/// the captured bytes.
async fn spawn_loopback_capture_server() -> (u16, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // Read whatever the client sends in the first chunk — enough to
        // capture the request line + headers for assertion.
        let mut buf = vec![0u8; 8192];
        let n = socket.read(&mut buf).await.expect("read request");
        let captured = String::from_utf8_lossy(&buf[..n]).to_string();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        socket.write_all(resp).await.expect("write response");
        socket.flush().await.ok();
        captured
    });
    (port, handle)
}

/// Regression for the `fetch_with_bearer` double-"Bearer" 401 bug.
///
/// `SecretProvider::into_auth_header(slot, "Authorization")` ALREADY
/// prepends `"Bearer "`. The bug prepended a SECOND `"Bearer "`, sending
/// `Authorization: Bearer Bearer <token>` → every upstream rejected it
/// with 401 (first seen against api.github.com via github-pr-reviewer).
/// This test drives a real `fetch_with_bearer` against a loopback server
/// and asserts the wire header is exactly `Bearer <token>` (single prefix).
#[tokio::test]
async fn fetch_with_bearer_sends_single_bearer_prefix() {
    // The loopback target is a private IP; the per-execution SSRF resolver
    // would block it without this dev-only bypass. nextest runs each test in
    // its own process, so the env var is isolated to this test.
    std::env::set_var("WORKER_ALLOW_PRIVATE_HOST_TARGETS", "1");
    // The loopback server speaks plaintext HTTP; opt into insecure outbound
    // so the scheme gate doesn't reject it before we reach fetch_with_bearer.
    std::env::set_var("WASM_ALLOW_INSECURE_HTTP", "1");

    let (port, server) = spawn_loopback_capture_server().await;

    let mut secrets = HashMap::new();
    secrets.insert("test/token".to_string(), "ghs_testtoken12345".to_string());

    let mut ctx = TalosContext::new(
        CapabilityWorld::Secrets,
        // Use the `localhost` HOSTNAME (not a 127.0.0.1 IP *literal*): the
        // host-entry `denied_ip_literal` gate unconditionally blocks private
        // IP literals, but a hostname is checked at connect time by the
        // per-execution SSRF resolver — which DOES honour the
        // WORKER_ALLOW_PRIVATE_HOST_TARGETS bypass when the host is in this
        // explicit allowlist (no `*`). So `localhost` reaches the loopback
        // server while still exercising the real fetch_with_bearer path.
        vec!["localhost".to_string()],
        vec![],
        128,
        secrets,
        None,
        None,
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::default(),
    )
    .unwrap();

    // Grant the secret path — an empty allowlist is deny-all, so without
    // this grant get_secret returns Unauthorized. `test/token` is NOT a
    // reserved host path (not an LLM-provider / OAuth-refresh key), so the
    // grant is honoured.
    ctx.set_allowed_secrets(vec!["test/token".to_string()]);

    // Resolve the secret path to a host-internal u64 slot exactly the way a
    // guest module would (via the guest-facing get-secret host fn).
    let slot = <TalosContext as crate::bindings::talos::core::secrets::Host>::get_secret(
        &mut ctx,
        "test/token".to_string(),
    )
    .await
    .expect("get_secret should resolve the in-memory secret to a slot");

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: format!("http://localhost:{}/", port),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };

    let resp = ctx.fetch_with_bearer(slot, req).await;
    assert!(
        resp.is_ok(),
        "fetch_with_bearer should reach the loopback server: {:?}",
        resp.err()
    );

    let captured = server.await.expect("server task");

    // Find the Authorization header line and assert the single-prefix value.
    let auth_line = captured
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .expect("request must carry an Authorization header");
    let value = auth_line
        .split_once(':')
        .map(|(_, v)| v.trim())
        .unwrap_or("");
    assert_eq!(
        value, "Bearer ghs_testtoken12345",
        "Authorization header must carry exactly one Bearer prefix"
    );
    // Core regression guard: the double-prefix substring must NOT appear.
    assert!(
        !captured.contains("Bearer Bearer"),
        "request must NOT contain a doubled `Bearer Bearer` prefix (the 401 bug)"
    );

    std::env::remove_var("WORKER_ALLOW_PRIVATE_HOST_TARGETS");
    std::env::remove_var("WASM_ALLOW_INSECURE_HTTP");
}

/// Regression for the local-LLM SSRF-bypass fix: the dedicated
/// `local_llm_http_client()` (used for local Ollama in `wit_llm::complete`
/// when `is_local`) must NOT carry the per-execution SSRF-filtering DNS
/// resolver — local Ollama lives on a private IP (loopback / LAN), which
/// the guest SSRF-filtered client correctly blocks. This proves the local
/// client can reach a private loopback target.
#[tokio::test]
async fn local_llm_client_reaches_private_loopback() {
    let (port, server) = spawn_loopback_capture_server().await;

    let resp = crate::host_impl::local_llm_http_client()
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await;

    assert!(
        resp.is_ok(),
        "local_llm_http_client must reach a private loopback IP (Ollama egress): {:?}",
        resp.as_ref().err()
    );
    assert_eq!(
        resp.unwrap().status(),
        200,
        "loopback server should return 200"
    );

    // Drain the server task so it doesn't leak.
    let _ = server.await;
}
