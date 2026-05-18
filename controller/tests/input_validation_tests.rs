//! Security boundary tests for input validation edge cases.
//!
//! These tests exercise the controller's actual validation functions against
//! adversarial input: null bytes, CRLF injection, oversized strings, Unicode
//! edge cases, empty strings, and deeply nested JSON.

use controller::api::validation::{
    validate_json_field, validate_payload_size, validate_resource_name, validate_safe_identifier,
    validate_safe_url, validate_uuid,
};

// ---------------------------------------------------------------------------
// Null-byte injection
// ---------------------------------------------------------------------------

#[test]
fn null_byte_in_workflow_name_is_rejected() {
    let name = "my-workflow\0-evil";
    let result = validate_resource_name(name);
    assert!(
        result.is_err(),
        "Null bytes in resource names must be rejected"
    );
}

#[test]
fn null_byte_in_module_name_is_rejected() {
    let name = "module\0injected";
    let result = validate_resource_name(name);
    assert!(
        result.is_err(),
        "Null bytes in module names must be rejected"
    );
}

#[test]
fn null_byte_in_identifier_is_rejected() {
    let id = "safe_id\0evil";
    let result = validate_safe_identifier(id);
    assert!(
        result.is_err(),
        "Null bytes in identifiers must be rejected"
    );
}

// ---------------------------------------------------------------------------
// CRLF injection in fields
// ---------------------------------------------------------------------------

#[test]
fn crlf_injection_in_name_is_rejected() {
    let name = "Normal\r\nX-Injected-Header: evil";
    let result = validate_resource_name(name);
    assert!(
        result.is_err(),
        "CRLF sequences in resource names must be rejected"
    );
}

#[test]
fn newline_in_name_is_rejected() {
    let name = "line1\nline2";
    let result = validate_resource_name(name);
    assert!(
        result.is_err(),
        "Newlines in resource names must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Very long strings
// ---------------------------------------------------------------------------

#[test]
fn very_long_name_is_rejected() {
    let long_name = "A".repeat(256);
    let result = validate_resource_name(&long_name);
    assert!(
        result.is_err(),
        "Names exceeding 255 characters must be rejected"
    );
}

#[test]
fn name_at_max_length_is_accepted() {
    let name = "A".repeat(255);
    let result = validate_resource_name(&name);
    assert!(
        result.is_ok(),
        "Names at exactly 255 characters should pass"
    );
}

#[test]
fn payload_exceeding_10mb_limit_is_rejected() {
    let huge = "X".repeat(10 * 1024 * 1024 + 1);
    let result = validate_payload_size("graph_json", &huge);
    assert!(result.is_err(), "Payloads over 10 MB must be rejected");
}

#[test]
fn payload_exactly_at_10mb_limit_is_accepted() {
    let exact = "Y".repeat(10 * 1024 * 1024);
    let result = validate_payload_size("graph_json", &exact);
    assert!(
        result.is_ok(),
        "Payload at exactly 10 MB should be accepted"
    );
}

// ---------------------------------------------------------------------------
// Unicode edge cases
// ---------------------------------------------------------------------------

#[test]
fn rtl_override_characters_in_identifier() {
    // Right-to-left override (U+202E) can visually mask strings
    let name = "safe\u{202E}txt";
    let result = validate_safe_identifier(name);
    assert!(
        result.is_err(),
        "RTL override characters must be rejected in identifiers"
    );
}

#[test]
fn zero_width_joiner_in_identifier() {
    let name = "ad\u{200D}min";
    let result = validate_safe_identifier(name);
    assert!(
        result.is_err(),
        "Zero-width joiners must be rejected in identifiers"
    );
}

// ---------------------------------------------------------------------------
// Path traversal and injection characters
// ---------------------------------------------------------------------------

#[test]
fn path_traversal_in_name_is_rejected() {
    assert!(validate_resource_name("../../etc/passwd").is_err());
    assert!(validate_resource_name("..\\windows\\system32").is_err());
    assert!(validate_resource_name("name/with/slashes").is_err());
}

#[test]
fn shell_injection_characters_rejected() {
    assert!(validate_resource_name("name<script>").is_err());
    assert!(validate_resource_name("name|pipe").is_err());
    assert!(validate_resource_name("name\"quoted").is_err());
}

#[test]
fn hidden_file_names_rejected() {
    assert!(validate_resource_name(".hidden").is_err());
    assert!(validate_resource_name("..parent").is_err());
}

#[test]
fn reserved_windows_names_rejected() {
    assert!(validate_resource_name("CON").is_err());
    assert!(validate_resource_name("com1").is_err());
    assert!(validate_resource_name("LPT1").is_err());
    assert!(validate_resource_name("NUL").is_err());
}

// ---------------------------------------------------------------------------
// Empty and whitespace-only inputs
// ---------------------------------------------------------------------------

#[test]
fn empty_workflow_name_is_rejected() {
    assert!(validate_resource_name("").is_err());
}

#[test]
fn whitespace_only_workflow_name_is_rejected() {
    assert!(validate_resource_name("   \t\n  ").is_err());
}

#[test]
fn empty_identifier_is_rejected() {
    assert!(validate_safe_identifier("").is_err());
}

// ---------------------------------------------------------------------------
// Deeply nested JSON
// ---------------------------------------------------------------------------

#[test]
fn deeply_nested_json_beyond_limit_is_rejected() {
    let depth = 150;
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"a":"#);
    }
    json.push_str(r#""leaf""#);
    for _ in 0..depth {
        json.push('}');
    }

    let result = validate_json_field("test_field", &json);
    assert!(
        result.is_err(),
        "JSON exceeding nesting depth limit must be rejected"
    );
}

#[test]
fn deeply_nested_json_within_limit_is_accepted() {
    let depth = 50;
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"a":"#);
    }
    json.push_str(r#""leaf""#);
    for _ in 0..depth {
        json.push('}');
    }

    let result = validate_json_field("test_field", &json);
    assert!(result.is_ok(), "50-level nesting should be accepted");
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

#[test]
fn javascript_url_scheme_rejected() {
    assert!(validate_safe_url("javascript:alert(1)").is_err());
}

#[test]
fn data_url_scheme_rejected() {
    assert!(validate_safe_url("data:text/html,<script>alert(1)</script>").is_err());
}

#[test]
fn valid_https_url_accepted() {
    assert!(validate_safe_url("https://example.com/webhook").is_ok());
}

// ---------------------------------------------------------------------------
// UUID validation
// ---------------------------------------------------------------------------

#[test]
fn valid_uuid_accepted() {
    assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
}

#[test]
fn malformed_uuid_rejected() {
    assert!(validate_uuid("not-a-uuid").is_err());
    assert!(validate_uuid("").is_err());
    assert!(validate_uuid("550e8400-e29b-41d4-a716").is_err());
}
