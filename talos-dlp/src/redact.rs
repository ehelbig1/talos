//! # Key-based JSON redaction
//!
//! Complements the value-based [`crate::ExecutionContext`] scrubber with a
//! key-oriented pass that replaces any JSON object value whose KEY matches
//! one of the sensitive-key patterns defined in [`crate::policy`] with a
//! fixed redaction placeholder. This covers cases where the sensitive value
//! hasn't been seen by the execution context yet — for example, when
//! surfacing a captured module input to a human operator via the
//! `generate_typed_scaffold` sample-capture path.
//!
//! ## Design
//!
//! - **In-place mutation** via `&mut Value` avoids cloning a large payload
//!   twice. Callers that need the original should clone before calling.
//! - **Recursion depth is bounded** to 256 levels. JSON nested deeper than
//!   that is almost certainly adversarial; the function returns early and
//!   leaves remaining deep levels untouched rather than stack-overflowing.
//! - **Array handling**: we recurse into array elements so that arrays of
//!   objects get their sensitive child keys redacted. The array itself is
//!   never treated as a sensitive key (arrays have no key).
//! - **Placeholder is a constant string** (`"[REDACTED]"`) — callers that
//!   need a different placeholder should post-process the output. Using a
//!   literal keeps the redactor dependency-free and lets downstream
//!   consumers grep for the marker.
//!
//! ## Security
//!
//! The key-based pass is pattern-matching on metadata (the field name),
//! not content, so it does not leak the raw value — we overwrite before
//! any caller can see the original. Defense-in-depth: operators should
//! still run the value-based [`crate::ExecutionContext::redact_output`]
//! pass after this one, since the two layers catch different classes of
//! leak.

use serde_json::Value;

use crate::policy::is_sensitive_key;

/// Placeholder string written over any field value whose key matches
/// a sensitive-key pattern.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Maximum recursion depth when walking a JSON value tree. Matches the
/// cap used by the XML parser in host_impl.rs so the two layers agree on
/// "pathological nesting".
const MAX_REDACT_DEPTH: usize = 256;

/// Walk `value` in place and replace the value of any JSON object field
/// whose key matches a sensitive-key pattern with `REDACTED_PLACEHOLDER`.
///
/// - Objects with a sensitive key: the value at that key becomes
///   `Value::String("[REDACTED]")`, regardless of original type.
/// - Arrays: each element is recursed into; elements themselves are not
///   inspected as keys (arrays have no keys).
/// - Primitives at the root: left unchanged — there's no key to compare.
///
/// Recursion depth is capped at 256 levels to prevent stack overflow on
/// adversarially-nested input. Levels beyond the cap are left untouched.
pub fn redact_sensitive_keys(value: &mut Value) {
    redact_recursive(value, 0);
}

fn redact_recursive(value: &mut Value, depth: usize) {
    if depth >= MAX_REDACT_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *val = Value::String(REDACTED_PLACEHOLDER.to_string());
                } else {
                    redact_recursive(val, depth + 1);
                }
            }
        }
        Value::Array(arr) => {
            for elem in arr.iter_mut() {
                redact_recursive(elem, depth + 1);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_top_level_sensitive_key() {
        let mut v = json!({
            "username": "alice",
            "api_key": "sk-1234567890abcdef",
        });
        redact_sensitive_keys(&mut v);
        assert_eq!(v["username"], "alice");
        assert_eq!(v["api_key"], "[REDACTED]");
    }

    #[test]
    fn redacts_nested_sensitive_key() {
        let mut v = json!({
            "config": {
                "endpoint": "https://api.example.com",
                "auth_token": "bearer-xyz"
            }
        });
        redact_sensitive_keys(&mut v);
        assert_eq!(v["config"]["endpoint"], "https://api.example.com");
        assert_eq!(v["config"]["auth_token"], "[REDACTED]");
    }

    #[test]
    fn redacts_sensitive_keys_in_array_of_objects() {
        // Note: `is_sensitive_key` matches patterns with leading underscore
        // (e.g. `_PASSWORD`), so plain `password` would not match but
        // `user_password` does. Mirrors the policy.rs contract.
        let mut v = json!({
            "users": [
                { "name": "alice", "user_password": "s3cret1" },
                { "name": "bob", "user_password": "s3cret2" }
            ]
        });
        redact_sensitive_keys(&mut v);
        assert_eq!(v["users"][0]["name"], "alice");
        assert_eq!(v["users"][0]["user_password"], "[REDACTED]");
        assert_eq!(v["users"][1]["name"], "bob");
        assert_eq!(v["users"][1]["user_password"], "[REDACTED]");
    }

    #[test]
    fn leaves_non_sensitive_keys_intact() {
        let mut v = json!({
            "endpoint": "https://example.com",
            "timeout": 30,
            "retries": 3
        });
        let before = v.clone();
        redact_sensitive_keys(&mut v);
        assert_eq!(v, before);
    }

    #[test]
    fn preserves_shape_on_primitive_root() {
        // Primitive roots have no key — redactor must be a no-op.
        let mut v = json!("api_key");
        redact_sensitive_keys(&mut v);
        assert_eq!(v, json!("api_key"));

        let mut v = json!(42);
        redact_sensitive_keys(&mut v);
        assert_eq!(v, json!(42));
    }

    #[test]
    fn redacts_value_regardless_of_original_type() {
        // A sensitive-key field may hold a number, array, or object — all
        // should be overwritten with the string placeholder.
        let mut v = json!({
            "num_secret": 42,
            "arr_secret": [1, 2, 3],
            "obj_secret": { "nested": true }
        });
        redact_sensitive_keys(&mut v);
        assert_eq!(v["num_secret"], "[REDACTED]");
        assert_eq!(v["arr_secret"], "[REDACTED]");
        assert_eq!(v["obj_secret"], "[REDACTED]");
    }

    #[test]
    fn handles_mixed_case_sensitive_keys() {
        let mut v = json!({
            "API_KEY": "x",
            "Api_Key": "y",
            "apiKey": "z"
        });
        redact_sensitive_keys(&mut v);
        assert_eq!(v["API_KEY"], "[REDACTED]");
        assert_eq!(v["Api_Key"], "[REDACTED]");
        // is_sensitive_key uppercases before matching "_KEY" as a substring.
        // "apiKey" uppercases to "APIKEY" which does NOT contain "_KEY" —
        // this is the documented behavior of SENSITIVE_KEY_PATTERNS.
        assert_eq!(v["apiKey"], "z");
    }

    #[test]
    fn depth_cap_prevents_stack_overflow() {
        // Build a deeply-nested object that would blow the stack if we
        // recursed without a cap. The redactor should return cleanly and
        // leave the top levels scrubbed where applicable.
        let mut current = json!({"leaf": "value"});
        for _ in 0..1000 {
            current = json!({"nested": current, "api_key": "secret"});
        }
        // This must not panic.
        redact_sensitive_keys(&mut current);
        // Top-level api_key is within the depth cap, so it should be
        // redacted.
        assert_eq!(current["api_key"], "[REDACTED]");
    }

    #[test]
    fn redacts_in_nested_array_of_arrays() {
        // `api_token` → uppercased `API_TOKEN` contains `_TOKEN`, so this
        // matches the policy patterns. Plain `token` would not.
        let mut v = json!({
            "batches": [
                [{"api_token": "a"}, {"api_token": "b"}],
                [{"api_token": "c"}]
            ]
        });
        redact_sensitive_keys(&mut v);
        assert_eq!(v["batches"][0][0]["api_token"], "[REDACTED]");
        assert_eq!(v["batches"][0][1]["api_token"], "[REDACTED]");
        assert_eq!(v["batches"][1][0]["api_token"], "[REDACTED]");
    }
}
