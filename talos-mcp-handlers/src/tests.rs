use super::utils::{resource_not_found_error, validate_dependencies};
use super::*;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

// Mock AgentIdentity for testing RBAC
fn mock_agent(capabilities: Vec<&str>) -> Arc<crate::auth::AgentIdentity> {
    Arc::new(crate::auth::AgentIdentity {
        agent_id: Uuid::new_v4(),
        name: "Test Agent".to_string(),
        role_name: "test-role".to_string(),
        allowed_capabilities: capabilities.into_iter().map(|s| s.to_string()).collect(),
        user_id: None,
    })
}

#[test]
fn test_handle_initialize() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let resp = handle_initialize(req);
    assert_eq!(resp.jsonrpc, "2.0");
    assert_eq!(resp.id, Some(json!(1)));

    let result = resp.result.unwrap();
    assert_eq!(result["serverInfo"]["name"], "Talos Native MCP Server");
}

#[test]
fn test_mock_agent_capabilities() {
    let agent = mock_agent(vec!["network", "secrets"]);
    assert_eq!(agent.name, "Test Agent");
    assert_eq!(agent.allowed_capabilities.len(), 2);
    assert!(agent.allowed_capabilities.contains(&"network".to_string()));
}

#[test]
fn test_json_rpc_error_serialization() {
    let err = JsonRpcError {
        code: -32601,
        message: "Method not found".to_string(),
        data: None,
    };
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["code"], -32601);
    assert_eq!(json["message"], "Method not found");
    assert!(json.get("data").is_none());
}

#[tokio::test]
async fn test_handle_tools_list_rbac_minimal() {
    // Basic test for initialize since full RBAC requires DB
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };
    let resp = handle_initialize(req);
    assert!(resp.error.is_none());
}

#[test]
fn test_json_rpc_request_deserialization() {
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
    assert_eq!(req.method, "tools/list");
    assert_eq!(req.id, Some(json!(1)));
}

#[test]
fn test_resource_not_found_error_helper() {
    let id = Some(json!("req-123"));
    let uri = "talos://invalid";
    let resp = resource_not_found_error(id.clone(), uri);

    assert_eq!(resp.id, id);
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32001);
    assert!(err.message.contains(uri));
}

// =========================================================================
// Dependency allowlist validation
// =========================================================================

#[test]
fn validate_deps_accepts_approved_crate() {
    let deps = json!({"serde": "1.0", "chrono": "0.4"});
    assert!(validate_dependencies(Some(&deps)).is_ok());
}

#[test]
fn validate_deps_accepts_all_default_allowed_crates() {
    let deps = json!({
        "serde": "1.0",
        "serde_json": "1.0",
        // reqwest removed: incompatible with wasm32-wasip2 (links browser wasm-bindgen bindings)
        "chrono": "0.4",
        "uuid": "1.0",
        "base64": "0.22",
        "url": "2.5",
        "regex": "1.12",
        "tokio": "1.0",
        "anyhow": "1.0",
        "thiserror": "2.0",
        "rand": "0.8",
        "sha2": "0.10",
        "hmac": "0.12",
        "http": "1.0"
    });
    assert!(validate_dependencies(Some(&deps)).is_ok());
}

#[test]
fn validate_deps_rejects_unapproved_crate() {
    let deps = json!({"malicious_crate": "0.1"});
    let result = validate_dependencies(Some(&deps));
    assert!(result.is_err(), "unapproved crate should be rejected");
    assert!(result.unwrap_err().contains("Disallowed"));
}

#[test]
fn validate_deps_rejects_reqwest() {
    // reqwest links against wasm-bindgen browser JS bindings incompatible with wasm32-wasip2.
    // It must not appear on the allowlist — use the WIT HTTP host interface instead.
    let deps = json!({"reqwest": "0.12"});
    let result = validate_dependencies(Some(&deps));
    assert!(
        result.is_err(),
        "reqwest should be rejected (wasm32-wasip2 incompatible)"
    );
    assert!(result.unwrap_err().contains("Disallowed"));
}

#[test]
fn validate_deps_rejects_multiple_unapproved_crates() {
    let deps = json!({"evil1": "0.1", "evil2": "0.2"});
    let result = validate_dependencies(Some(&deps));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("evil1") || err.contains("evil2"));
}

#[test]
fn validate_deps_rejects_wildcard_version() {
    let deps = json!({"serde": "*"});
    let result = validate_dependencies(Some(&deps));
    assert!(result.is_err(), "wildcard version should be rejected");
    assert!(result.unwrap_err().contains("wildcard"));
}

#[test]
fn validate_deps_rejects_empty_version() {
    let deps = json!({"serde": ""});
    let result = validate_dependencies(Some(&deps));
    assert!(result.is_err(), "empty version should be rejected");
}

#[test]
fn validate_deps_accepts_none() {
    assert!(
        validate_dependencies(None).is_ok(),
        "no dependencies should pass"
    );
}

#[test]
fn validate_deps_accepts_empty_object() {
    let deps = json!({});
    assert!(
        validate_dependencies(Some(&deps)).is_ok(),
        "empty deps should pass"
    );
}

#[test]
fn validate_deps_accepts_null() {
    let deps = serde_json::Value::Null;
    assert!(
        validate_dependencies(Some(&deps)).is_ok(),
        "null deps should pass"
    );
}

#[test]
fn validate_deps_is_case_insensitive_for_crate_names() {
    let deps = json!({"SERDE": "1.0"});
    assert!(
        validate_dependencies(Some(&deps)).is_ok(),
        "crate name check should be case-insensitive"
    );
}

// =========================================================================
// Per-agent rate limiter
// =========================================================================

#[test]
fn rate_limiter_allows_requests_under_limit() {
    let limiter = AgentRateLimiter::new(5);
    for _ in 0..5 {
        assert!(
            limiter.check_and_increment("agent-1"),
            "should allow up to limit"
        );
    }
}

#[test]
fn rate_limiter_blocks_requests_over_limit() {
    let limiter = AgentRateLimiter::new(3);
    for _ in 0..3 {
        assert!(limiter.check_and_increment("agent-2"));
    }
    assert!(
        !limiter.check_and_increment("agent-2"),
        "should block after limit exceeded"
    );
}

#[test]
fn rate_limiter_tracks_agents_independently() {
    let limiter = AgentRateLimiter::new(2);
    assert!(limiter.check_and_increment("agent-a"));
    assert!(limiter.check_and_increment("agent-a"));
    assert!(
        !limiter.check_and_increment("agent-a"),
        "agent-a should be blocked"
    );

    // agent-b should still be allowed
    assert!(
        limiter.check_and_increment("agent-b"),
        "agent-b should still be allowed"
    );
    assert!(limiter.check_and_increment("agent-b"));
    assert!(!limiter.check_and_increment("agent-b"));
}

#[test]
fn rate_limiter_resets_after_window_expires() {
    use std::time::Duration;

    // Use a window long enough that two consecutive `check_and_increment`
    // calls reliably land inside it on any reasonable runner. The original
    // 1ms window flaked under CI timing pressure (the second call would
    // sometimes cross the boundary and pass instead of being blocked).
    // 50ms is generous and the post-expiry sleep below is a 5x multiple.
    let window = Duration::from_millis(50);
    let limiter = AgentRateLimiter {
        windows: dashmap::DashMap::new(),
        max_requests: 1,
        window_duration: window,
    };

    assert!(limiter.check_and_increment("agent-x"));
    assert!(
        !limiter.check_and_increment("agent-x"),
        "should be blocked while inside the window"
    );

    // Wait comfortably past the window so the next call reliably resets.
    std::thread::sleep(window * 5);

    assert!(
        limiter.check_and_increment("agent-x"),
        "should be allowed after window reset"
    );
}

/// MCP-1178: at the defense-in-depth cap, NEW keys are refused as
/// rate-limited while EXISTING tracked keys continue through their
/// normal accounting (cap doesn't punish keys already under quota).
#[test]
fn rate_limiter_fails_closed_at_cap_for_new_keys() {
    use std::time::{Duration, Instant};

    let limiter = AgentRateLimiter {
        windows: dashmap::DashMap::new(),
        max_requests: 1000,
        // Long window so wedge entries stay fresh and retain finds
        // nothing to evict — that's the exact burst scenario this
        // test exercises.
        window_duration: Duration::from_secs(600),
    };

    // Wedge to exactly the cap with sentinel keys (don't depend on
    // real agent_id shapes).
    let now = Instant::now();
    for i in 0..AGENT_RATE_LIMITER_MAX_ENTRIES {
        limiter.windows.insert(format!("wedge-{}", i), (1, now));
    }
    assert_eq!(limiter.windows.len(), AGENT_RATE_LIMITER_MAX_ENTRIES);

    // NEW key at-cap: rejected (treated as rate-limited).
    assert!(
        !limiter.check_and_increment("brand-new-agent"),
        "new key must be refused when rate limiter at cap"
    );
    // Map didn't grow — the gated path returned without inserting.
    assert_eq!(limiter.windows.len(), AGENT_RATE_LIMITER_MAX_ENTRIES);

    // EXISTING key at-cap: still flows through accounting (this is
    // the 2nd request for wedge-0, well under max_requests=1000).
    assert!(
        limiter.check_and_increment("wedge-0"),
        "existing key must keep flowing through rate-limit accounting at cap"
    );
    // Still at cap (existing key touched in-place, no new entry).
    assert_eq!(limiter.windows.len(), AGENT_RATE_LIMITER_MAX_ENTRIES);
}
