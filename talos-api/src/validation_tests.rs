//! Tests for validation functions

use super::*;

// ============================================================================
// validate_payload_size tests
// ============================================================================

#[test]
fn test_validate_payload_size_accepts_under_limit() {
    let payload = "a".repeat(1024); // 1KB
    assert!(validate_payload_size("test", &payload).is_ok());
}

#[test]
fn test_validate_payload_size_rejects_over_limit() {
    let payload = "a".repeat(11 * 1024 * 1024); // 11MB
    let result = validate_payload_size("test", &payload);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("exceeds maximum size"));
}

#[test]
fn test_validate_payload_size_exactly_at_limit() {
    let payload = "a".repeat(10 * 1024 * 1024); // Exactly 10MB
    assert!(validate_payload_size("test", &payload).is_ok());
}

#[test]
fn test_validate_payload_size_empty() {
    assert!(validate_payload_size("test", "").is_ok());
}

// ============================================================================
// validate_resource_name tests
// ============================================================================

#[test]
fn test_validate_resource_name_accepts_valid_name() {
    assert!(validate_resource_name("my-workflow").is_ok());
    assert!(validate_resource_name("my_workflow").is_ok());
    assert!(validate_resource_name("MyWorkflow123").is_ok());
}

#[test]
fn test_validate_resource_name_rejects_empty() {
    let result = validate_resource_name("");
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("cannot be empty"));
}

#[test]
fn test_validate_resource_name_rejects_whitespace_only() {
    let result = validate_resource_name("   ");
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("cannot be empty"));
}

#[test]
fn test_validate_resource_name_rejects_path_traversal_slash() {
    let result = validate_resource_name("../etc/passwd");
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("forbidden character"));
}

#[test]
fn test_validate_resource_name_rejects_backslash() {
    let result = validate_resource_name("file\\name");
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("forbidden character"));
}

#[test]
fn test_validate_resource_name_rejects_null_byte() {
    let result = validate_resource_name("test\0name");
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("forbidden character"));
}

#[test]
fn test_validate_resource_name_rejects_newline() {
    let result = validate_resource_name("test\nname");
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("forbidden character"));
}

#[test]
fn test_validate_resource_name_rejects_carriage_return() {
    let result = validate_resource_name("test\rname");
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("forbidden character"));
}

#[test]
fn test_validate_resource_name_rejects_hidden_file() {
    let result = validate_resource_name(".hidden");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message
        .contains("cannot start with a dot"));
}

#[test]
fn test_validate_resource_name_rejects_reserved_windows_names() {
    // Test Windows reserved filenames
    for name in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"] {
        let result = validate_resource_name(name);
        assert!(result.is_err(), "{} should be rejected", name);
        assert!(result
            .unwrap_err()
            .message
            .contains("reserved system filename"));
    }
}

#[test]
fn test_validate_resource_name_rejects_reserved_case_insensitive() {
    let result = validate_resource_name("con");
    assert!(result.is_err());
    let result = validate_resource_name("Con");
    assert!(result.is_err());
    let result = validate_resource_name("CON");
    assert!(result.is_err());
}

#[test]
fn test_validate_resource_name_rejects_too_long() {
    let name = "a".repeat(256);
    let result = validate_resource_name(&name);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message
        .contains("exceeds maximum length"));
}

#[test]
fn test_validate_resource_name_accepts_max_length() {
    let name = "a".repeat(255);
    assert!(validate_resource_name(&name).is_ok());
}

#[test]
fn test_validate_resource_name_trims_whitespace() {
    // Leading/trailing whitespace should be trimmed
    assert!(validate_resource_name("  valid-name  ").is_ok());
}

#[test]
fn test_validate_resource_name_rejects_angle_brackets() {
    let result = validate_resource_name("test<script>");
    assert!(result.is_err());
    let result = validate_resource_name(">script");
    assert!(result.is_err());
}

#[test]
fn test_validate_resource_name_rejects_colon() {
    let result = validate_resource_name("C:drive");
    assert!(result.is_err());
}

#[test]
fn test_validate_resource_name_rejects_pipe() {
    let result = validate_resource_name("file|name");
    assert!(result.is_err());
}

#[test]
fn test_validate_resource_name_rejects_question_mark() {
    let result = validate_resource_name("file?name");
    assert!(result.is_err());
}

#[test]
fn test_validate_resource_name_rejects_asterisk() {
    let result = validate_resource_name("file*name");
    assert!(result.is_err());
}

#[test]
fn test_validate_resource_name_rejects_quote() {
    let result = validate_resource_name("file\"name");
    assert!(result.is_err());
}

// ============================================================================
// validate_safe_identifier tests
// ============================================================================

#[test]
fn test_validate_safe_identifier_accepts_valid() {
    assert!(validate_safe_identifier("my-identifier").is_ok());
    assert!(validate_safe_identifier("my_identifier").is_ok());
    assert!(validate_safe_identifier("MyIdentifier123").is_ok());
    assert!(validate_safe_identifier("a").is_ok());
}

#[test]
fn test_validate_safe_identifier_rejects_empty() {
    let result = validate_safe_identifier("");
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("cannot be empty"));
}

#[test]
fn test_validate_safe_identifier_rejects_leading_hyphen() {
    let result = validate_safe_identifier("-identifier");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message
        .contains("cannot start or end with a hyphen"));
}

#[test]
fn test_validate_safe_identifier_rejects_trailing_hyphen() {
    let result = validate_safe_identifier("identifier-");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message
        .contains("cannot start or end with a hyphen"));
}

#[test]
fn test_validate_safe_identifier_rejects_special_chars() {
    assert!(validate_safe_identifier("id@name").is_err());
    assert!(validate_safe_identifier("id#name").is_err());
    assert!(validate_safe_identifier("id$name").is_err());
    assert!(validate_safe_identifier("id.name").is_err());
    assert!(validate_safe_identifier("id/name").is_err());
}

#[test]
fn test_validate_safe_identifier_rejects_too_long() {
    let id = "a".repeat(65);
    let result = validate_safe_identifier(&id);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message
        .contains("exceeds maximum length"));
}

#[test]
fn test_validate_safe_identifier_accepts_max_length() {
    let id = "a".repeat(64);
    assert!(validate_safe_identifier(&id).is_ok());
}

#[test]
fn test_validate_safe_identifier_accepts_underscores() {
    assert!(validate_safe_identifier("my_test_id").is_ok());
    assert!(validate_safe_identifier("_private").is_ok());
    assert!(validate_safe_identifier("private_").is_ok());
}

// ============================================================================
// validate_string_length tests
// ============================================================================

#[test]
fn test_validate_string_length_accepts_under_limit() {
    assert!(validate_string_length("field", "hello", 10).is_ok());
}

#[test]
fn test_validate_string_length_rejects_over_limit() {
    let result = validate_string_length("field", "hello world", 5);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message
        .contains("exceeds maximum length"));
}

#[test]
fn test_validate_string_length_exactly_at_limit() {
    assert!(validate_string_length("field", "hello", 5).is_ok());
}

#[test]
fn test_validate_string_length_empty() {
    assert!(validate_string_length("field", "", 10).is_ok());
}

// ============================================================================
// validate_text_field tests
// ============================================================================

#[test]
fn test_validate_text_field_accepts_large_text() {
    let text = "a".repeat(1000 * 1024); // 1MB
    assert!(validate_text_field("description", &text).is_ok());
}

#[test]
fn test_validate_text_field_rejects_too_large() {
    let text = "a".repeat(2 * 1024 * 1024); // 2MB, exceeds 1MB limit
    let result = validate_text_field("description", &text);
    assert!(result.is_err());
}

// ============================================================================
// validate_short_text_field tests
// ============================================================================

#[test]
fn test_validate_short_text_field_accepts_short_text() {
    let text = "a".repeat(1000);
    assert!(validate_short_text_field("description", &text).is_ok());
}

#[test]
fn test_validate_short_text_field_rejects_too_long() {
    let text = "a".repeat(10_001); // Just over 10K limit
    let result = validate_short_text_field("description", &text);
    assert!(result.is_err());
}

// ============================================================================
// validate_json_field tests
// ============================================================================

#[test]
fn test_validate_json_field_accepts_valid_json() {
    let json = r#"{"key": "value"}"#;
    assert!(validate_json_field("config", json).is_ok());
}

#[test]
fn test_validate_json_field_accepts_large_json() {
    // 10MB is the limit for JSON
    let json = format!("{{\"data\": \"{}\"}}", "a".repeat(10 * 1024 * 1024 - 20));
    assert!(validate_json_field("config", &json).is_ok());
}

#[test]
fn test_validate_json_field_rejects_too_large() {
    let json = format!("{{\"data\": \"{}\"}}", "a".repeat(11 * 1024 * 1024));
    let result = validate_json_field("config", &json);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message
        .contains("exceeds maximum JSON payload size"));
}

// ============================================================================
// validate_max_concurrent_executions tests (MCP-1182)
// ============================================================================

#[test]
fn test_validate_max_concurrent_executions_accepts_none() {
    // None = clear the cap, always valid
    assert!(validate_max_concurrent_executions(None).is_ok());
}

#[test]
fn test_validate_max_concurrent_executions_accepts_canonical_range() {
    for n in [1, 5, 25, 50, 100] {
        assert!(
            validate_max_concurrent_executions(Some(n)).is_ok(),
            "must accept canonical value: {n}"
        );
    }
}

#[test]
fn test_validate_max_concurrent_executions_rejects_zero() {
    // 0 would collapse admit_count to 0 → workflow can't execute
    let err = validate_max_concurrent_executions(Some(0)).unwrap_err();
    assert!(err.message.contains("Invalid max_concurrent_executions"));
}

#[test]
fn test_validate_max_concurrent_executions_rejects_negative() {
    // -1 falls through admit_count helper's .max(0) into headroom=0 → DoS
    let err = validate_max_concurrent_executions(Some(-1)).unwrap_err();
    assert!(err.message.contains("Invalid max_concurrent_executions"));
}

#[test]
fn test_validate_max_concurrent_executions_rejects_above_max() {
    // 101 onward: bypass the per-workflow throttle that protects the
    // shared worker fleet from a runaway dispatch loop
    let err = validate_max_concurrent_executions(Some(101)).unwrap_err();
    assert!(err.message.contains("Invalid max_concurrent_executions"));
}

#[test]
fn test_validate_max_concurrent_executions_rejects_i32_max() {
    // i32::MAX is the worst-case bypass payload — effectively no cap
    let err = validate_max_concurrent_executions(Some(i32::MAX)).unwrap_err();
    assert!(err.message.contains("Invalid max_concurrent_executions"));
}

// ============================================================================
// validate_secret_value tests (MCP-1186)
// ============================================================================

#[test]
fn test_validate_secret_value_accepts_canonical_secret() {
    // Typical secrets: API keys, tokens, short passwords
    for value in ["sk-abc123", "ghp_abc123def456", "Bearer xyz789"] {
        assert!(
            validate_secret_value(value).is_ok(),
            "must accept canonical secret: {value}"
        );
    }
}

#[test]
fn test_validate_secret_value_accepts_multiline_pem() {
    // PEM keys carry legitimate trailing newlines
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n";
    assert!(validate_secret_value(pem).is_ok());
}

#[test]
fn test_validate_secret_value_rejects_whitespace_only() {
    for value in ["", "   ", "\n\n", "\t"] {
        let err = validate_secret_value(value).unwrap_err();
        assert!(
            err.message.contains("non-whitespace"),
            "must reject whitespace-only value: {value:?}"
        );
    }
}

#[test]
fn test_validate_secret_value_accepts_at_cap() {
    // 64 KiB exactly should be accepted
    let value = "a".repeat(64 * 1024);
    assert!(validate_secret_value(&value).is_ok());
}

#[test]
fn test_validate_secret_value_rejects_over_cap() {
    // 64 KiB + 1 byte should be rejected
    let value = "a".repeat(64 * 1024 + 1);
    let err = validate_secret_value(&value).unwrap_err();
    assert!(err.message.contains("exceeds maximum size"));
}

#[test]
fn test_validate_secret_value_rejects_1mb_payload() {
    // The pre-fix GraphQL cap was 1 MiB; this confirms we now refuse
    // payloads that the loose pre-fix gate would have accepted.
    let value = "a".repeat(1024 * 1024);
    assert!(validate_secret_value(&value).is_err());
}

// ============================================================================
// validate_api_key_expires_in_days tests (MCP-1187)
// ============================================================================

#[test]
fn test_validate_api_key_expires_in_days_accepts_none() {
    // None = non-expiring key, always valid
    assert!(validate_api_key_expires_in_days(None).is_ok());
}

#[test]
fn test_validate_api_key_expires_in_days_accepts_canonical_values() {
    for n in [1, 7, 30, 90, 180, 365, 730, 3650] {
        assert!(
            validate_api_key_expires_in_days(Some(n)).is_ok(),
            "must accept canonical value: {n}"
        );
    }
}

#[test]
fn test_validate_api_key_expires_in_days_rejects_zero() {
    // 0 produces same-second expiration → key unusable
    let err = validate_api_key_expires_in_days(Some(0)).unwrap_err();
    assert!(err.message.contains("Invalid expires_in_days"));
}

#[test]
fn test_validate_api_key_expires_in_days_rejects_negative() {
    // Negative produces past expiration → key unusable
    let err = validate_api_key_expires_in_days(Some(-1)).unwrap_err();
    assert!(err.message.contains("Invalid expires_in_days"));
}

#[test]
fn test_validate_api_key_expires_in_days_rejects_above_10_years() {
    // 3651+ exceeds the 10-year ceiling
    let err = validate_api_key_expires_in_days(Some(3651)).unwrap_err();
    assert!(err.message.contains("Invalid expires_in_days"));
}

#[test]
fn test_validate_api_key_expires_in_days_rejects_i64_max() {
    // The DoS payload: i64::MAX would panic chrono::Duration::days
    // on overflow if it reached the chrono path. Refuse at the
    // boundary so the panic surface is never exercised.
    let err = validate_api_key_expires_in_days(Some(i64::MAX)).unwrap_err();
    assert!(err.message.contains("Invalid expires_in_days"));
}

// ============================================================================
// validate_workflow_execution_timeout tests (MCP-1216)
// ============================================================================

#[test]
fn test_validate_workflow_execution_timeout_accepts_missing_field() {
    // No execution_timeout_secs → engine uses default; accept.
    let g = r#"{"nodes": [], "edges": []}"#;
    assert!(validate_workflow_execution_timeout(g).is_ok());
}

#[test]
fn test_validate_workflow_execution_timeout_accepts_typical_value() {
    // daily-brief sets 120; well within cap.
    let g = r#"{"nodes": [], "execution_timeout_secs": 120}"#;
    assert!(validate_workflow_execution_timeout(g).is_ok());
}

#[test]
fn test_validate_workflow_execution_timeout_accepts_zero() {
    // 0 = "disabled" sentinel; engine falls back to default. Allowed
    // because the engine itself treats 0 specially — the API
    // boundary should match.
    let g = r#"{"execution_timeout_secs": 0}"#;
    assert!(validate_workflow_execution_timeout(g).is_ok());
}

#[test]
fn test_validate_workflow_execution_timeout_accepts_at_cap() {
    let g = format!(
        r#"{{"execution_timeout_secs": {}}}"#,
        MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS
    );
    assert!(validate_workflow_execution_timeout(&g).is_ok());
}

#[test]
fn test_validate_workflow_execution_timeout_rejects_above_cap() {
    let g = format!(
        r#"{{"execution_timeout_secs": {}}}"#,
        MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS + 1
    );
    let err = validate_workflow_execution_timeout(&g).unwrap_err();
    assert!(err.message.contains("Invalid execution_timeout_secs"));
    assert!(err.message.contains("exceeds"));
}

#[test]
fn test_validate_workflow_execution_timeout_rejects_24h() {
    // The canonical attack value: 86400 = 24 hours.
    let g = r#"{"execution_timeout_secs": 86400}"#;
    let err = validate_workflow_execution_timeout(g).unwrap_err();
    assert!(err.message.contains("86400"));
}

#[test]
fn test_validate_workflow_execution_timeout_rejects_u64_max() {
    let g = format!(r#"{{"execution_timeout_secs": {}}}"#, u64::MAX);
    assert!(validate_workflow_execution_timeout(&g).is_err());
}

#[test]
fn test_validate_workflow_execution_timeout_ignores_negative() {
    // The engine's parser uses `.as_u64()` which returns None for
    // negative i64; engine then falls back to default. Match that
    // behavior — let the canonical parser own the malformed case.
    let g = r#"{"execution_timeout_secs": -1}"#;
    assert!(validate_workflow_execution_timeout(g).is_ok());
}

#[test]
fn test_validate_workflow_execution_timeout_ignores_float() {
    // `.as_u64()` is None for floats too.
    let g = r#"{"execution_timeout_secs": 60.5}"#;
    assert!(validate_workflow_execution_timeout(g).is_ok());
}

#[test]
fn test_validate_workflow_execution_timeout_ignores_string() {
    // Non-numeric → engine ignores → API boundary matches.
    let g = r#"{"execution_timeout_secs": "60"}"#;
    assert!(validate_workflow_execution_timeout(g).is_ok());
}

#[test]
fn test_validate_workflow_execution_timeout_handles_malformed_json() {
    // Malformed JSON: defer to the engine's parser for the canonical
    // error. The validator should not double-error here.
    let g = "{not valid json";
    assert!(validate_workflow_execution_timeout(g).is_ok());
}

#[test]
fn test_validate_workflow_execution_timeout_cap_is_one_hour() {
    // Tripwire: the 1-hour ceiling matches the documented operator-
    // decision context. Bumping it should land in a reviewed commit.
    assert_eq!(MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS, 3600);
}
