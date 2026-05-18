use serde_json::Value;

use crate::policy::is_sensitive_key;
use crate::secret::SecretValue;

/// Per-execution holder of sensitive config values.
///
/// Built once from the node configs at the start of each workflow execution.
/// Provides value-based redaction that complements the regex-based DLP layer —
/// any literal secret value found in module output or error messages is masked
/// regardless of its format.
///
/// `vault://` references in node configs are **not** wrapped as secrets here
/// because they are opaque paths, not the actual plaintext secret. The host
/// layer resolves vault paths to real values only at the HTTP boundary.
pub struct ExecutionContext {
    secrets: Vec<SecretValue>,
}

impl ExecutionContext {
    /// Build an `ExecutionContext` by scanning all node configs for fields whose
    /// keys match [`SENSITIVE_KEY_PATTERNS`].
    ///
    /// Rules:
    /// - `__`-prefixed keys are skipped (internal talos metadata).
    /// - `vault://` references are skipped (opaque path, not the real value).
    /// - Values shorter than 4 characters are skipped (too short → high false-positive risk).
    pub fn from_node_configs<'a>(configs: impl Iterator<Item = &'a Value>) -> Self {
        let mut secrets = Vec::new();
        for config in configs {
            if let Some(obj) = config.as_object() {
                for (key, val) in obj {
                    if key.starts_with("__") {
                        continue;
                    }
                    if !is_sensitive_key(key) {
                        continue;
                    }
                    if let Some(s) = val.as_str() {
                        if s.starts_with("vault://") {
                            continue; // opaque path — not the plaintext secret
                        }
                        if s.len() >= 4 {
                            secrets.push(SecretValue::new(s.to_string(), key.as_str(), key));
                        }
                    }
                }
            }
        }
        Self { secrets }
    }

    /// Returns `true` if no sensitive values were found in the node configs.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Recursively walk a JSON value tree and replace any string leaf that contains
    /// a known secret with `[REDACTED:SECRET]`.
    ///
    /// This is a **value-based** pass. It should be followed by the regex-based
    /// DLP pass (`crate::dlp::redact_json`) for defense in depth.
    pub fn redact_output(&self, value: &Value) -> Value {
        if self.is_empty() {
            return value.clone();
        }
        redact_json_recursive(value, &self.secrets)
    }

    /// Replace any occurrence of a known secret in `error` with `[REDACTED:SECRET]`.
    ///
    /// This is a **value-based** pass. It should be followed by the regex-based
    /// DLP pass (`crate::dlp::redact_str`) for defense in depth.
    pub fn redact_error(&self, error: &str) -> String {
        let mut result = error.to_string();
        for sv in &self.secrets {
            if let std::borrow::Cow::Owned(s) = sv.redact_from_str(&result) {
                result = s;
            }
        }
        result
    }
}

fn redact_json_recursive(value: &Value, secrets: &[SecretValue]) -> Value {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for sv in secrets {
                if let std::borrow::Cow::Owned(s) = sv.redact_from_str(&result) {
                    result = s;
                }
            }
            Value::String(result)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| redact_json_recursive(v, secrets))
                .collect(),
        ),
        Value::Object(map) => {
            let mut new_map = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                new_map.insert(k.clone(), redact_json_recursive(v, secrets));
            }
            Value::Object(new_map)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
// `vec![one_value]` reads more naturally than `[one_value]` in test
// fixtures here — every test threads the collection through `.iter()`,
// and the `vec!` form makes the intent (a list of inputs) consistent
// with the multi-element fixtures alongside.
#[allow(clippy::useless_vec)]
mod tests {
    use super::*;

    #[test]
    fn test_from_node_configs_empty() {
        let configs: Vec<Value> = vec![];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_no_sensitive_keys() {
        let configs = vec![serde_json::json!({"url": "https://api.example.com", "timeout": 30})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_extracts_api_key() {
        let configs =
            vec![serde_json::json!({"API_KEY": "secret123", "url": "https://api.example.com"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        assert!(!ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_extracts_multiple_secrets() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123", "DB_PASSWORD": "dbpass456"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        assert!(!ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_skips_vault_refs() {
        let configs = vec![serde_json::json!({"API_KEY": "vault://secrets/key"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        // vault:// refs should be skipped
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_skips_internal_keys() {
        let configs = vec![serde_json::json!({"__internal_secret": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        // __-prefixed keys should be skipped
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_skips_short_values() {
        let configs = vec![
            serde_json::json!({"API_KEY": "ab"}), // Less than 4 chars
        ];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        // Short values should be skipped
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_preserves_exactly_4_chars() {
        let configs = vec![
            serde_json::json!({"API_KEY": "abcd"}), // Exactly 4 chars
        ];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        // Exactly 4 chars should be kept
        assert!(!ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_handles_non_object() {
        let configs = vec![
            serde_json::json!("not an object"),
            serde_json::json!(123),
            serde_json::json!([1, 2, 3]),
        ];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_from_node_configs_handles_null() {
        let configs = vec![serde_json::json!({"API_KEY": null})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_redact_error_with_no_secrets() {
        let configs: Vec<Value> = vec![];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let error = "An error occurred with secret123";
        let result = ctx.redact_error(error);
        assert_eq!(result, error);
    }

    #[test]
    fn test_redact_error_replaces_secret() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let error = "Failed with secret123 in the message";
        let result = ctx.redact_error(error);
        assert_eq!(result, "Failed with [REDACTED:SECRET] in the message");
    }

    #[test]
    fn test_redact_error_replaces_multiple_secrets() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123", "DB_PASSWORD": "dbpass456"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let error = "API: secret123, DB: dbpass456";
        let result = ctx.redact_error(error);
        assert_eq!(result, "API: [REDACTED:SECRET], DB: [REDACTED:SECRET]");
    }

    #[test]
    fn test_redact_output_string() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let value = Value::String("The secret is secret123".to_string());
        let result = ctx.redact_output(&value);
        assert_eq!(
            result,
            Value::String("The secret is [REDACTED:SECRET]".to_string())
        );
    }

    #[test]
    fn test_redact_output_object() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let value = serde_json::json!({
            "message": "The secret is secret123",
            "data": {
                "token": "secret123 here too"
            }
        });
        let result = ctx.redact_output(&value);
        let expected = serde_json::json!({
            "message": "The secret is [REDACTED:SECRET]",
            "data": {
                "token": "[REDACTED:SECRET] here too"
            }
        });
        assert_eq!(result, expected);
    }

    #[test]
    fn test_redact_output_array() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let value = serde_json::json!(["secret123", "normal", {"key": "secret123"}]);
        let result = ctx.redact_output(&value);
        let expected =
            serde_json::json!(["[REDACTED:SECRET]", "normal", {"key": "[REDACTED:SECRET]"}]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_redact_output_empty_context_no_change() {
        let configs: Vec<Value> = vec![];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let value = serde_json::json!({"message": "secret123"});
        let result = ctx.redact_output(&value);
        // Should return clone of original
        assert_eq!(result, value);
    }

    #[test]
    fn test_redact_output_preserves_numbers_and_bools() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let value = serde_json::json!({
            "count": 42,
            "active": true,
            "message": "secret123"
        });
        let result = ctx.redact_output(&value);
        let expected = serde_json::json!({
            "count": 42,
            "active": true,
            "message": "[REDACTED:SECRET]"
        });
        assert_eq!(result, expected);
    }

    #[test]
    fn test_redact_output_deeply_nested() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let value = serde_json::json!({
            "level1": {
                "level2": {
                    "level3": {
                        "secret": "secret123"
                    }
                }
            }
        });
        let result = ctx.redact_output(&value);
        let expected = serde_json::json!({
            "level1": {
                "level2": {
                    "level3": {
                        "secret": "[REDACTED:SECRET]"
                    }
                }
            }
        });
        assert_eq!(result, expected);
    }

    #[test]
    fn test_case_insensitive_key_matching() {
        let configs = vec![
            serde_json::json!({"api_key": "lowercase"}),
            serde_json::json!({"API_KEY": "uppercase"}),
            serde_json::json!({"Api_Key": "mixed"}),
        ];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        assert!(!ctx.is_empty());
        // All should be detected and redacted
        let error = "lowercase uppercase mixed";
        let result = ctx.redact_error(error);
        assert!(!result.contains("lowercase"));
        assert!(!result.contains("uppercase"));
        assert!(!result.contains("mixed"));
    }

    #[test]
    fn test_redact_output_empty_string() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let value = Value::String("".to_string());
        let result = ctx.redact_output(&value);
        assert_eq!(result, Value::String("".to_string()));
    }

    #[test]
    fn test_redact_error_empty_string() {
        let configs = vec![serde_json::json!({"API_KEY": "secret123"})];
        let ctx = ExecutionContext::from_node_configs(configs.iter());
        let result = ctx.redact_error("");
        assert_eq!(result, "");
    }
}
