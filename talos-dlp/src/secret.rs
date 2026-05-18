use secrecy::{ExposeSecret, Secret};
use std::borrow::Cow;
use std::fmt;

/// A secret string value that cannot be accidentally printed or serialized.
///
/// - `Display` is **not** implemented — using `{}` in a format string is a compile error.
/// - `serde::Serialize` is **not** implemented — `serde_json::to_string(&secret)` is a compile error.
/// - `Debug` shows `[REDACTED:<key_path>]` — safe to include in log output.
/// - [`expose_for_http`] is the single auditable exit point for reading the plaintext.
///
/// `grep -rn "expose_for_http" worker/src/` should return exactly one result.
pub struct SecretValue {
    inner: Secret<String>,
    key_path: String,
}

impl SecretValue {
    /// Wrap a plaintext value as a secret.
    ///
    /// * `value` — the plaintext secret string
    /// * `key_path` — human-readable identifier used in `Debug` output (e.g. `"vault://aws/key"`)
    /// * `_field_name` — reserved for future audit logging; currently unused
    pub fn new(value: String, key_path: impl Into<String>, _field_name: &str) -> Self {
        Self {
            inner: Secret::new(value),
            key_path: key_path.into(),
        }
    }

    /// **The only way to read the plaintext secret.**
    ///
    /// This function name is intentionally grep-able so that every call site
    /// can be audited with a single command:
    /// ```text
    /// grep -rn "expose_for_http" worker/src/
    /// ```
    /// The caller is responsible for ensuring the returned `&str` is used only
    /// to construct an outbound HTTP request header and is not stored, logged,
    /// or returned to the guest.
    pub fn expose_for_http(&self) -> &str {
        self.inner.expose_secret()
    }

    /// Replace any occurrence of this secret's plaintext in `text` with `[REDACTED:SECRET]`.
    ///
    /// Secrets shorter than 4 characters are skipped to avoid replacing common substrings.
    /// Returns `Cow::Borrowed` when no replacement is needed (zero allocation in the common case).
    pub fn redact_from_str<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let val = self.inner.expose_secret();
        if val.len() >= 4 && text.contains(val.as_str()) {
            Cow::Owned(text.replace(val.as_str(), "[REDACTED:SECRET]"))
        } else {
            Cow::Borrowed(text)
        }
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:{}]", self.key_path)
    }
}

// Explicitly opt out of Display and Serialize so misuse is a compile error.
// (Neither is implemented, so no explicit `impl !Display` needed in stable Rust.)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_secret() {
        let secret = SecretValue::new("my-secret".to_string(), "vault://test/key", "apiKey");
        assert_eq!(secret.expose_for_http(), "my-secret");
    }

    #[test]
    fn test_expose_for_http_returns_plaintext() {
        let secret = SecretValue::new("super-secret-value".to_string(), "path", "field");
        assert_eq!(secret.expose_for_http(), "super-secret-value");
    }

    #[test]
    fn test_redact_from_str_replaces_secret() {
        let secret = SecretValue::new("secret123".to_string(), "path", "field");
        let text = "The password is secret123 and it is secret";
        let result = secret.redact_from_str(text);
        assert_eq!(result, "The password is [REDACTED:SECRET] and it is secret");
    }

    #[test]
    fn test_redact_from_str_skips_short_secrets() {
        let secret = SecretValue::new("ab".to_string(), "path", "field");
        let text = "The secret is ab";
        let result = secret.redact_from_str(text);
        // Short secrets (< 4 chars) should not be redacted
        assert_eq!(result, "The secret is ab");
    }

    #[test]
    fn test_redact_from_str_returns_borrowed_when_no_match() {
        let secret = SecretValue::new("secret123".to_string(), "path", "field");
        let text = "This text does not contain the secret";
        let result = secret.redact_from_str(text);
        // Should return Cow::Borrowed for zero-allocation path
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_from_str_returns_owned_when_match() {
        let secret = SecretValue::new("secret123".to_string(), "path", "field");
        let text = "The secret123 is here";
        let result = secret.redact_from_str(text);
        // Should return Cow::Owned when replacement happens
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_debug_shows_redacted() {
        let secret = SecretValue::new(
            "should-not-appear".to_string(),
            "vault://aws/api-key",
            "apiKey",
        );
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED:vault://aws/api-key]");
        assert!(!debug_output.contains("should-not-appear"));
    }

    #[test]
    fn test_redact_from_str_multiple_occurrences() {
        let secret = SecretValue::new("password".to_string(), "path", "field");
        let text = "password is the password for the password field";
        let result = secret.redact_from_str(text);
        assert_eq!(
            result,
            "[REDACTED:SECRET] is the [REDACTED:SECRET] for the [REDACTED:SECRET] field"
        );
    }

    #[test]
    fn test_redact_from_str_exactly_4_chars() {
        // Boundary test: exactly 4 characters should be redacted
        let secret = SecretValue::new("abcd".to_string(), "path", "field");
        let text = "The code is abcd here";
        let result = secret.redact_from_str(text);
        assert_eq!(result, "The code is [REDACTED:SECRET] here");
    }

    #[test]
    fn test_redact_from_str_3_chars_not_redacted() {
        // Boundary test: 3 characters should NOT be redacted
        let secret = SecretValue::new("abc".to_string(), "path", "field");
        let text = "The code is abc here";
        let result = secret.redact_from_str(text);
        assert_eq!(result, "The code is abc here");
    }

    #[test]
    fn test_empty_secret_not_redacted() {
        let secret = SecretValue::new("".to_string(), "path", "field");
        let text = "Some text";
        let result = secret.redact_from_str(text);
        assert_eq!(result, "Some text");
    }

    #[test]
    fn test_redact_in_json_like_string() {
        let secret = SecretValue::new("sk-abc123".to_string(), "path", "field");
        let text = r#"{"api_key": "sk-abc123", "url": "https://api.example.com"}"#;
        let result = secret.redact_from_str(text);
        assert_eq!(
            result,
            r#"{"api_key": "[REDACTED:SECRET]", "url": "https://api.example.com"}"#
        );
    }
}
