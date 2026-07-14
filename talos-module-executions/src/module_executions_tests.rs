// Unit tests for ModuleExecutionService security features
// Tests cover: UTF-8 handling, authorization, JSONB size limits, sanitization

use super::ModuleExecutionService;
use serde_json::json;

// ==================== UTF-8 Boundary Tests ====================

#[test]
fn test_sanitize_error_message_ascii_only() {
    let message = "a".repeat(5000);
    let result = ModuleExecutionService::sanitize_error_message(message.clone());
    assert_eq!(result, message);
}

#[test]
fn test_sanitize_error_message_unicode_safe() {
    // Test with emojis (4-byte UTF-8 characters)
    let message = "a".repeat(9999) + "🔥🔥🔥";
    let result = ModuleExecutionService::sanitize_error_message(message);
    // Should not panic!
    assert!(!result.is_empty());
}

#[test]
fn test_sanitize_error_message_truncates_correctly() {
    let message = "x".repeat(15000);
    let result = ModuleExecutionService::sanitize_error_message(message);

    // Should be truncated
    assert!(result.contains("truncated"));
    assert!(result.contains("5000 more characters"));

    // First 10,000 characters should be preserved
    let truncated_part: String = result.chars().take(10000).collect();
    assert_eq!(truncated_part, "x".repeat(10000));
}

#[test]
fn test_sanitize_error_message_chinese_characters() {
    // Chinese characters are 3-byte UTF-8
    let message = "你好世界".repeat(3000); // ~12,000 characters
    let result = ModuleExecutionService::sanitize_error_message(message);

    // Should not panic and should truncate
    assert!(result.contains("truncated"));

    // Verify no partial characters at boundary
    assert!(result.chars().nth(9999).is_some());
}

#[test]
fn test_sanitize_error_message_strips_control_characters() {
    let message = "Hello\x00\x01\x02World\x1B[31mRed\x1B[0m".to_string();
    let result = ModuleExecutionService::sanitize_error_message(message);

    // Control characters should be stripped
    assert!(!result.contains("\x00"));
    assert!(!result.contains("\x01"));
    assert!(!result.contains("\x1B"));

    // Normal characters should remain
    assert!(result.contains("Hello"));
    assert!(result.contains("World"));
    assert!(result.contains("Red"));
}

#[test]
fn test_sanitize_error_message_preserves_newlines_tabs() {
    let message = "Line 1\nLine 2\tTabbed\rCarriage".to_string();
    let result = ModuleExecutionService::sanitize_error_message(message);

    // Newlines, tabs, carriage returns should be preserved
    assert!(result.contains("\n"));
    assert!(result.contains("\t"));
    assert!(result.contains("\r"));
}

// ==================== JSONB Size Validation Tests ====================

#[test]
fn test_validate_jsonb_size_none() {
    let result = ModuleExecutionService::validate_jsonb_size(&None, "test_field");
    assert!(result.is_ok());
}

#[test]
fn test_validate_jsonb_size_small_json() {
    let json = Some(json!({"key": "value"}));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "test_field");
    assert!(result.is_ok());
}

#[test]
fn test_validate_jsonb_size_exactly_at_limit() {
    // Create JSON that's exactly 1MB when serialized
    let large_string = "x".repeat(1_048_500); // Just under 1MB
    let json = Some(json!({"data": large_string}));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "test_field");

    // Should be accepted (under limit)
    assert!(result.is_ok());
}

#[test]
fn test_validate_jsonb_size_exceeds_limit() {
    // Create JSON that exceeds 1MB
    let huge_string = "x".repeat(2_000_000); // 2MB
    let json = Some(json!({"data": huge_string}));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "test_field");

    // Should be rejected
    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Data size limit exceeded"));
}

#[test]
fn test_validate_jsonb_size_complex_nested_json() {
    // Create complex nested JSON
    let json = Some(json!({
        "level1": {
            "level2": {
                "level3": {
                    "data": "x".repeat(100_000)
                }
            }
        }
    }));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "nested_field");

    // Should be accepted (under 1MB)
    assert!(result.is_ok());
}

// ==================== Integration Tests ====================

#[test]
fn test_max_constants_are_reasonable() {
    // Verify constants are set to reasonable values
    assert_eq!(ModuleExecutionService::MAX_LOGS_PER_EXECUTION, 1000);
    assert_eq!(ModuleExecutionService::MAX_ERROR_MESSAGE_LENGTH, 10_000);
    assert_eq!(ModuleExecutionService::MAX_JSONB_SIZE_BYTES, 1_048_576); // 1MB
    assert_eq!(ModuleExecutionService::MAX_LOG_MESSAGE_LENGTH, 10_000);
}

#[test]
fn test_sanitize_handles_empty_string() {
    let message = String::new();
    let result = ModuleExecutionService::sanitize_error_message(message);
    assert_eq!(result, "");
}

#[test]
fn test_sanitize_handles_single_character() {
    let message = "a".to_string();
    let result = ModuleExecutionService::sanitize_error_message(message);
    assert_eq!(result, "a");
}

#[test]
fn test_sanitize_handles_exactly_max_length() {
    let message = "x".repeat(10_000);
    let result = ModuleExecutionService::sanitize_error_message(message.clone());
    assert_eq!(result, message);
    assert!(!result.contains("truncated"));
}

#[test]
fn test_sanitize_handles_one_over_max_length() {
    let message = "x".repeat(10_001);
    let result = ModuleExecutionService::sanitize_error_message(message);
    assert!(result.contains("truncated"));
    assert!(result.contains("1 more character"));
}

// ==================== Edge Cases ====================

#[test]
fn test_sanitize_all_control_characters() {
    // String with only control characters
    let message = "\x00\x01\x02\x03\x04\x05".to_string();
    let result = ModuleExecutionService::sanitize_error_message(message);

    // Should result in empty or minimal string (control chars stripped)
    assert!(result.len() < 10);
}

#[test]
fn test_sanitize_mixed_valid_invalid() {
    let message = "Valid\x00Invalid\x1BMore".to_string();
    let result = ModuleExecutionService::sanitize_error_message(message);

    // Valid parts should remain
    assert!(result.contains("Valid"));
    assert!(result.contains("Invalid"));
    assert!(result.contains("More"));

    // Invalid parts should be gone
    assert!(!result.contains("\x00"));
    assert!(!result.contains("\x1B"));
}

#[test]
fn test_validate_jsonb_with_null_values() {
    let json = Some(json!({"key": null}));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "null_field");
    assert!(result.is_ok());
}

#[test]
fn test_validate_jsonb_with_boolean() {
    let json = Some(json!({"flag": true, "other": false}));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "bool_field");
    assert!(result.is_ok());
}

#[test]
fn test_validate_jsonb_with_numbers() {
    let json = Some(json!({
        "int": 123,
        "float": 1.5,
        "big": 999999999
    }));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "number_field");
    assert!(result.is_ok());
}

#[test]
fn test_validate_jsonb_with_array() {
    let large_array: Vec<String> = (0..10000).map(|i| format!("item_{}", i)).collect();
    let json = Some(json!(large_array));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "array_field");

    // 10K small strings should be under 1MB
    assert!(result.is_ok());
}

#[test]
fn test_validate_jsonb_huge_array_rejected() {
    let huge_array: Vec<String> = (0..200000)
        .map(|i| format!("long_item_name_{}", i))
        .collect();
    let json = Some(json!(huge_array));
    let result = ModuleExecutionService::validate_jsonb_size(&json, "huge_array");

    // 200K items should exceed 1MB
    assert!(result.is_err());
}

// ==================== Status canonical-set pin ====================

#[test]
fn execution_status_all_round_trips_display() {
    // ALL mirrors the module_executions status CHECK constraint
    // (migrations/20260327000003). If a variant's rename and Display ever
    // disagree, or a CHECK value goes missing here, this fails. The
    // integration twin (controller/tests/module_execution_status_tests.rs)
    // proves the DECODE side against a real database — the direction that
    // silently drifted for 3.5 months when 'cancelled' was added to the
    // CHECK but not the enum.
    use super::ExecutionStatus;
    assert_eq!(ExecutionStatus::ALL.len(), 6);
    for (text, status) in ExecutionStatus::ALL {
        assert_eq!(&status.to_string(), text, "Display/rename drift for {text}");
    }
}
