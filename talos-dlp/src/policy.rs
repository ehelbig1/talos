/// Key name suffixes that indicate a config field likely holds a secret value.
///
/// Matching is case-insensitive (callers should uppercase the key before comparing).
/// Internal talos metadata keys (`__`-prefixed) are always excluded by the caller.
pub const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "_KEY",
    "_SECRET",
    "_TOKEN",
    "_PASSWORD",
    "_CREDENTIAL",
    "_PRIVATE",
    "_APIKEY",
    "_API_KEY",
    "_ACCESS_KEY",
    "_AUTH",
];

/// Returns `true` if `key` matches any of the [`SENSITIVE_KEY_PATTERNS`].
///
/// Comparison is case-insensitive.
pub fn is_sensitive_key(key: &str) -> bool {
    let upper = key.to_uppercase();
    SENSITIVE_KEY_PATTERNS.iter().any(|p| upper.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_patterns() {
        assert!(is_sensitive_key("MY_API_KEY"));
        assert!(is_sensitive_key("STRIPE_SECRET"));
        assert!(is_sensitive_key("DB_PASSWORD"));
        assert!(is_sensitive_key("AUTH_TOKEN"));
    }

    #[test]
    fn ignores_non_sensitive_keys() {
        assert!(!is_sensitive_key("endpoint"));
        assert!(!is_sensitive_key("url"));
        assert!(!is_sensitive_key("timeout"));
    }

    #[test]
    fn detects_credential_pattern() {
        assert!(is_sensitive_key("AWS_CREDENTIAL"));
        assert!(is_sensitive_key("my_credential_path")); // _CREDENTIAL anywhere in key
    }

    #[test]
    fn detects_private_pattern() {
        assert!(is_sensitive_key("SSH_PRIVATE_KEY"));
        assert!(is_sensitive_key("my_private_key"));
    }

    #[test]
    fn detects_token_pattern() {
        assert!(is_sensitive_key("BEARER_TOKEN"));
        assert!(is_sensitive_key("csrf_token_value"));
    }

    #[test]
    fn detects_apikey_pattern() {
        assert!(is_sensitive_key("STRIPE_APIKEY"));
        assert!(is_sensitive_key("MY_APIKEY_VALUE"));
    }

    #[test]
    fn detects_api_key_pattern() {
        assert!(is_sensitive_key("OPENAI_API_KEY"));
        assert!(is_sensitive_key("my_api_key"));
    }

    #[test]
    fn detects_access_key_pattern() {
        assert!(is_sensitive_key("AWS_ACCESS_KEY"));
        assert!(is_sensitive_key("access_key_id"));
    }

    #[test]
    fn detects_auth_pattern() {
        // _AUTH pattern must have underscore before AUTH
        assert!(is_sensitive_key("OAUTH_AUTH"));
        assert!(is_sensitive_key("header_auth"));
        assert!(!is_sensitive_key("auth_header")); // AUTH_ doesn't match _AUTH
    }

    #[test]
    fn case_insensitive_matching() {
        assert!(is_sensitive_key("api_key"));
        assert!(is_sensitive_key("Api_Key"));
        assert!(is_sensitive_key("API_KEY"));
        assert!(is_sensitive_key("aPi_KeY"));
    }

    #[test]
    fn empty_string_not_sensitive() {
        assert!(!is_sensitive_key(""));
    }

    #[test]
    fn pattern_requires_underscore_prefix() {
        // Keys without underscore prefix should NOT match
        assert!(!is_sensitive_key("SECRET_VALUE")); // no underscore before SECRET
        assert!(!is_sensitive_key("KEY_NAME")); // no underscore before KEY
        assert!(!is_sensitive_key("TOKEN")); // no underscore before TOKEN
    }

    #[test]
    fn partial_match_not_detected() {
        // Should NOT match partial patterns
        assert!(!is_sensitive_key("keynote"));
        assert!(!is_sensitive_key("tokenize"));
        assert!(!is_sensitive_key("passwordless")); // contains 'pass' but not '_password'
        assert!(!is_sensitive_key("authorized")); // contains 'auth' but not '_auth'
    }

    #[test]
    fn detects_patterns_with_underscores() {
        // Edge cases with multiple underscores
        assert!(is_sensitive_key("___KEY"));
        assert!(is_sensitive_key("__SECRET__"));
        assert!(is_sensitive_key("MY__API__KEY"));
    }

    #[test]
    fn long_key_with_pattern() {
        assert!(is_sensitive_key("VERY_LONG_KEY_NAME_WITH_API_KEY_IN_IT"));
    }

    #[test]
    fn detects_all_pattern_variants() {
        // Test all patterns in SENSITIVE_KEY_PATTERNS
        assert!(is_sensitive_key("DATA_KEY"));
        assert!(is_sensitive_key("APP_SECRET"));
        assert!(is_sensitive_key("AUTH_TOKEN"));
        assert!(is_sensitive_key("USER_PASSWORD"));
        assert!(is_sensitive_key("DB_CREDENTIAL"));
        assert!(is_sensitive_key("SSH_PRIVATE"));
        assert!(is_sensitive_key("STRIPE_APIKEY"));
        assert!(is_sensitive_key("SERVICE_API_KEY"));
        assert!(is_sensitive_key("AWS_ACCESS_KEY"));
        assert!(is_sensitive_key("OAUTH_AUTH"));
    }

    #[test]
    fn numbers_in_keys() {
        assert!(is_sensitive_key("API_KEY_1"));
        assert!(is_sensitive_key("_2FA_SECRET")); // _SECRET matches
    }

    #[test]
    fn pattern_at_start() {
        // Pattern can appear at start if it has underscore
        assert!(is_sensitive_key("_KEY_NAME"));
        assert!(is_sensitive_key("_SECRET"));
    }
}
