#[cfg(test)]
mod tests {
    use crate::{
        bool_env_or_default, execution_max_rows, execution_retention_days, get_allowed_origins,
        get_env, get_frontend_url, is_allowed_origin, positive_env_or_default,
        sanitize_oauth_error_code, validate_shared_secret_token,
    };
    use std::env;

    /// MCP-644 (2026-05-13): serialise tests that mutate process-global
    /// env vars. Without this guard, cargo's parallel test runner can
    /// race two tests that touch the same env var (e.g.
    /// `test_get_frontend_url_default` removes FRONTEND_URL while
    /// `test_get_frontend_url_custom` is in the middle of setting it),
    /// producing flaky failures that pass when run with
    /// `--test-threads=1` but fail under parallel. Mutex<()> guards
    /// the env-mutating critical section in each test — the pattern
    /// mirrors `talos-compilation::container::env_lock` and worker
    /// tests' ENV_LOCK.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        match LOCK.lock() {
            Ok(g) => g,
            // Poisoned by a panic in a prior test — recover so we don't
            // cascade failures. The env state may be dirty from the
            // panicking test; each test below re-sets/removes what it
            // cares about so recovery is safe.
            Err(poison) => poison.into_inner(),
        }
    }

    /// MCP-643: =0 must collapse to the default (with WARN at runtime;
    /// the test only verifies the return value here).
    #[test]
    fn test_positive_env_zero_substitutes_default() {
        let _g = env_lock();
        env::set_var("TEST_POS_ENV_ZERO", "0");
        let v: i32 = positive_env_or_default("TEST_POS_ENV_ZERO", 30);
        assert_eq!(v, 30);
        env::remove_var("TEST_POS_ENV_ZERO");
    }

    /// Negative values must also collapse to the default — destructive
    /// SQL `interval '-N days'` would archive future rows.
    #[test]
    fn test_positive_env_negative_substitutes_default() {
        let _g = env_lock();
        env::set_var("TEST_POS_ENV_NEG", "-5");
        let v: i32 = positive_env_or_default("TEST_POS_ENV_NEG", 30);
        assert_eq!(v, 30);
        env::remove_var("TEST_POS_ENV_NEG");
    }

    /// Missing env var → default.
    #[test]
    fn test_positive_env_missing_uses_default() {
        let _g = env_lock();
        env::remove_var("TEST_POS_ENV_MISSING_12345");
        let v: i32 = positive_env_or_default("TEST_POS_ENV_MISSING_12345", 30);
        assert_eq!(v, 30);
    }

    /// Invalid (non-numeric) value → default.
    #[test]
    fn test_positive_env_invalid_uses_default() {
        let _g = env_lock();
        env::set_var("TEST_POS_ENV_INVALID", "not-a-number");
        let v: i32 = positive_env_or_default("TEST_POS_ENV_INVALID", 30);
        assert_eq!(v, 30);
        env::remove_var("TEST_POS_ENV_INVALID");
    }

    /// Valid positive value passes through.
    #[test]
    fn test_positive_env_positive_passes_through() {
        let _g = env_lock();
        env::set_var("TEST_POS_ENV_POS", "60");
        let v: i32 = positive_env_or_default("TEST_POS_ENV_POS", 30);
        assert_eq!(v, 60);
        env::remove_var("TEST_POS_ENV_POS");
    }

    #[test]
    fn test_get_env_with_existing_var() {
        let _g = env_lock();
        env::set_var("TEST_CONFIG_VAR_1", "test_value");
        assert_eq!(get_env("TEST_CONFIG_VAR_1", "default"), "test_value");
        env::remove_var("TEST_CONFIG_VAR_1");
    }

    #[test]
    fn test_get_env_with_missing_var() {
        let _g = env_lock();
        env::remove_var("TEST_CONFIG_VAR_NONEXISTENT_12345");
        assert_eq!(
            get_env("TEST_CONFIG_VAR_NONEXISTENT_12345", "default_value"),
            "default_value"
        );
    }

    // MCP-615 (2026-05-12): empty-string env var must use the default
    // (not return ""). Helm `values.yaml` placeholders routinely produce
    // `KEY=""`; pre-fix `get_env` returned the empty string and shadowed
    // every downstream default. Single dedicated probe var keeps the
    // test from racing other tests in the same process.
    #[test]
    fn test_get_env_empty_string_falls_back_to_default() {
        let _g = env_lock();
        env::set_var("TEST_CONFIG_MCP_615_PROBE", "");
        assert_eq!(
            get_env("TEST_CONFIG_MCP_615_PROBE", "fallback_default"),
            "fallback_default",
            "empty env var must use the default (MCP-615)"
        );
        env::remove_var("TEST_CONFIG_MCP_615_PROBE");
    }

    #[test]
    fn test_get_frontend_url_default() {
        let _g = env_lock();
        env::remove_var("FRONTEND_URL");
        assert_eq!(get_frontend_url(), "http://localhost:3000");
    }

    #[test]
    fn test_get_frontend_url_custom() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "https://app.example.com");
        assert_eq!(get_frontend_url(), "https://app.example.com");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1000: a value with a path component must be rejected and
    /// fall back to the localhost default. The attacker shape:
    /// `FRONTEND_URL=https://attacker.com/redirect?to=` would otherwise
    /// produce `https://attacker.com/redirect?to=/settings?...` from
    /// the format! in slack/atlassian/gmail/oauth-callback handlers.
    #[test]
    fn test_get_frontend_url_path_rejected() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "https://attacker.com/redirect");
        assert_eq!(get_frontend_url(), "http://localhost:3000");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1000: trailing slash counts as a path; the inline validation
    /// in atlassian/gmail rejects it, so the helper does too. Operators
    /// hit the localhost fallback + WARN and fix the env to bare host.
    #[test]
    fn test_get_frontend_url_trailing_slash_rejected() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "https://app.example.com/");
        assert_eq!(get_frontend_url(), "http://localhost:3000");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1000: query-string smuggle. Defensive-only — wouldn't
    /// produce an open redirect on its own, but the concatenated URL is
    /// malformed and the safer posture is to refuse and warn.
    #[test]
    fn test_get_frontend_url_query_rejected() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "https://attacker.com?evil=1");
        assert_eq!(get_frontend_url(), "http://localhost:3000");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1000: fragment smuggle. Same rationale as the query case.
    #[test]
    fn test_get_frontend_url_fragment_rejected() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "https://app.example.com#evil");
        assert_eq!(get_frontend_url(), "http://localhost:3000");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1000: scheme-less values are rejected. An operator pasting
    /// `app.example.com` (no scheme) hits localhost-fallback instead of
    /// producing a relative redirect that would resolve against the
    /// controller host.
    #[test]
    fn test_get_frontend_url_no_scheme_rejected() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "app.example.com");
        assert_eq!(get_frontend_url(), "http://localhost:3000");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1000: port suffix is allowed (no path/query/fragment).
    #[test]
    fn test_get_frontend_url_with_port_accepted() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "https://app.example.com:8443");
        assert_eq!(get_frontend_url(), "https://app.example.com:8443");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1169: userinfo (`@`) rejected — `https://victim.com@attacker.com`
    /// would be parsed by browsers as navigation to attacker.com with
    /// userinfo `victim.com`. Pre-fix the validator accepted it.
    #[test]
    fn test_get_frontend_url_userinfo_rejected() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "https://victim.com@attacker.com");
        assert_eq!(get_frontend_url(), "http://localhost:3000");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1169: whitespace in the host portion is rejected. Pre-fix a
    /// stray space (`https://app.example .com`) would slip through and
    /// produce malformed URLs in `Location:` redirects.
    #[test]
    fn test_get_frontend_url_whitespace_rejected() {
        let _g = env_lock();
        env::set_var("FRONTEND_URL", "https://app.example .com");
        assert_eq!(get_frontend_url(), "http://localhost:3000");
        env::remove_var("FRONTEND_URL");
    }

    /// MCP-1169: control characters in the host portion are rejected
    /// (CRLF injection vector for `Location:` headers).
    #[test]
    fn test_get_frontend_url_crlf_rejected() {
        let _g = env_lock();
        env::set_var(
            "FRONTEND_URL",
            "https://app.example.com\r\nX-Injected: evil",
        );
        assert_eq!(get_frontend_url(), "http://localhost:3000");
        env::remove_var("FRONTEND_URL");
    }

    // ----- MCP-1094: sanitize_oauth_error_code -----

    #[test]
    fn test_sanitize_oauth_error_accepts_rfc6749_codes() {
        for code in [
            "invalid_request",
            "unauthorized_client",
            "access_denied",
            "unsupported_response_type",
            "invalid_scope",
            "server_error",
            "temporarily_unavailable",
        ] {
            assert_eq!(sanitize_oauth_error_code(code), code);
        }
    }

    #[test]
    fn test_sanitize_oauth_error_accepts_provider_extensions() {
        for code in [
            "interaction_required",
            "login_required",
            "consent_required",
            "account_selection_required",
            "invalid_grant",
            "invalid_client",
            "application_suspended",
            "invalid_team_for_non_distributed_app",
        ] {
            assert_eq!(sanitize_oauth_error_code(code), code);
        }
    }

    #[test]
    fn test_sanitize_oauth_error_rejects_uppercase() {
        assert_eq!(sanitize_oauth_error_code("Access_Denied"), "oauth_error");
        assert_eq!(sanitize_oauth_error_code("ACCESS_DENIED"), "oauth_error");
    }

    #[test]
    fn test_sanitize_oauth_error_rejects_whitespace_and_punctuation() {
        assert_eq!(
            sanitize_oauth_error_code("Your account suspended"),
            "oauth_error"
        );
        assert_eq!(
            sanitize_oauth_error_code("contact support@attacker.com"),
            "oauth_error"
        );
        assert_eq!(sanitize_oauth_error_code("a.b.c"), "oauth_error");
        assert_eq!(sanitize_oauth_error_code("a/b/c"), "oauth_error");
    }

    #[test]
    fn test_sanitize_oauth_error_rejects_oversize() {
        let big = "a".repeat(65);
        assert_eq!(sanitize_oauth_error_code(&big), "oauth_error");
        let at_cap = "a".repeat(64);
        assert_eq!(sanitize_oauth_error_code(&at_cap), at_cap);
    }

    #[test]
    fn test_sanitize_oauth_error_rejects_empty() {
        assert_eq!(sanitize_oauth_error_code(""), "oauth_error");
    }

    #[test]
    fn test_sanitize_oauth_error_rejects_control_chars() {
        assert_eq!(sanitize_oauth_error_code("invalid\n"), "oauth_error");
        assert_eq!(sanitize_oauth_error_code("invalid\0"), "oauth_error");
        assert_eq!(sanitize_oauth_error_code("\x07alert"), "oauth_error");
    }

    #[test]
    fn test_sanitize_oauth_error_rejects_non_ascii() {
        assert_eq!(sanitize_oauth_error_code("invälid"), "oauth_error");
        assert_eq!(sanitize_oauth_error_code("invalid 🦀"), "oauth_error");
    }

    #[test]
    fn test_execution_retention_days_default() {
        let _g = env_lock();
        env::remove_var("EXECUTION_RETENTION_DAYS");
        assert_eq!(execution_retention_days(), 30);
    }

    #[test]
    fn test_execution_retention_days_custom() {
        let _g = env_lock();
        env::set_var("EXECUTION_RETENTION_DAYS", "60");
        assert_eq!(execution_retention_days(), 60);
        env::remove_var("EXECUTION_RETENTION_DAYS");
    }

    #[test]
    fn test_execution_retention_days_invalid_uses_default() {
        let _g = env_lock();
        env::set_var("EXECUTION_RETENTION_DAYS", "not_a_number");
        assert_eq!(execution_retention_days(), 30);
        env::remove_var("EXECUTION_RETENTION_DAYS");
    }

    /// MCP-1063: `=0` substitutes the default. Pre-fix would have
    /// parsed cleanly to 0 → `INTERVAL '1 day' * 0` → matches every
    /// past execution → total purge of workflow_executions on the
    /// first sweep.
    #[test]
    fn test_execution_retention_days_zero_substitutes_default() {
        let _g = env_lock();
        env::set_var("EXECUTION_RETENTION_DAYS", "0");
        assert_eq!(execution_retention_days(), 30);
        env::remove_var("EXECUTION_RETENTION_DAYS");
    }

    /// MCP-1063: negative values are equally destructive (NOW() -
    /// negative = future, matches everything).
    #[test]
    fn test_execution_retention_days_negative_substitutes_default() {
        let _g = env_lock();
        env::set_var("EXECUTION_RETENTION_DAYS", "-5");
        assert_eq!(execution_retention_days(), 30);
        env::remove_var("EXECUTION_RETENTION_DAYS");
    }

    #[test]
    fn test_execution_max_rows_default() {
        let _g = env_lock();
        env::remove_var("EXECUTION_MAX_ROWS");
        assert_eq!(execution_max_rows(), 100_000);
    }

    #[test]
    fn test_execution_max_rows_custom() {
        let _g = env_lock();
        env::set_var("EXECUTION_MAX_ROWS", "50000");
        assert_eq!(execution_max_rows(), 50_000);
        env::remove_var("EXECUTION_MAX_ROWS");
    }

    /// MCP-1063: `=0` substitutes the default. `max_rows=0` would mean
    /// "evict every execution on cap-enforcement sweep".
    #[test]
    fn test_execution_max_rows_zero_substitutes_default() {
        let _g = env_lock();
        env::set_var("EXECUTION_MAX_ROWS", "0");
        assert_eq!(execution_max_rows(), 100_000);
        env::remove_var("EXECUTION_MAX_ROWS");
    }

    #[test]
    fn test_allowed_origins_parses_comma_separated() {
        let _g = env_lock();
        env::set_var("RUST_ENV", "development");
        env::set_var(
            "ALLOWED_ORIGIN",
            "http://localhost:3000,http://localhost:3001",
        );
        let origins = get_allowed_origins();
        assert!(origins.contains(&"http://localhost:3000".to_string()));
        assert!(origins.contains(&"http://localhost:3001".to_string()));
        env::remove_var("RUST_ENV");
        env::remove_var("ALLOWED_ORIGIN");
    }

    /// MCP-1060: canonical truthy tokens.
    #[test]
    fn test_bool_env_truthy_tokens() {
        let _g = env_lock();
        for v in &[
            "true", "TRUE", "True", "1", "yes", "YES", "on", "ON", "  on  ",
        ] {
            env::set_var("TEST_BOOL_ENV", v);
            assert!(
                bool_env_or_default("TEST_BOOL_ENV", false),
                "expected truthy: {:?}",
                v
            );
        }
        env::remove_var("TEST_BOOL_ENV");
    }

    /// MCP-1060: canonical falsy tokens.
    #[test]
    fn test_bool_env_falsy_tokens() {
        let _g = env_lock();
        for v in &["false", "FALSE", "0", "no", "NO", "off", "OFF", "  off  "] {
            env::set_var("TEST_BOOL_ENV2", v);
            assert!(
                !bool_env_or_default("TEST_BOOL_ENV2", true),
                "expected falsy: {:?}",
                v
            );
        }
        env::remove_var("TEST_BOOL_ENV2");
    }

    /// MCP-1060: unset returns default in both directions.
    #[test]
    fn test_bool_env_unset_returns_default() {
        let _g = env_lock();
        env::remove_var("TEST_BOOL_ENV_UNSET_55555");
        assert!(bool_env_or_default("TEST_BOOL_ENV_UNSET_55555", true));
        assert!(!bool_env_or_default("TEST_BOOL_ENV_UNSET_55555", false));
    }

    /// MCP-1060: empty string treated as unset (same shape as
    /// `get_env`'s MCP-615 fix — Helm placeholders set the var to `""`).
    #[test]
    fn test_bool_env_empty_returns_default() {
        let _g = env_lock();
        env::set_var("TEST_BOOL_ENV_EMPTY", "");
        assert!(bool_env_or_default("TEST_BOOL_ENV_EMPTY", true));
        assert!(!bool_env_or_default("TEST_BOOL_ENV_EMPTY", false));
        env::set_var("TEST_BOOL_ENV_EMPTY", "   ");
        assert!(bool_env_or_default("TEST_BOOL_ENV_EMPTY", true));
        assert!(!bool_env_or_default("TEST_BOOL_ENV_EMPTY", false));
        env::remove_var("TEST_BOOL_ENV_EMPTY");
    }

    /// MCP-1060: unrecognised values WARN + use default (not silently truthy).
    #[test]
    fn test_bool_env_unrecognised_returns_default() {
        let _g = env_lock();
        env::set_var("TEST_BOOL_ENV_GARBAGE", "enable");
        assert!(bool_env_or_default("TEST_BOOL_ENV_GARBAGE", true));
        assert!(!bool_env_or_default("TEST_BOOL_ENV_GARBAGE", false));
        env::set_var("TEST_BOOL_ENV_GARBAGE", "yarp");
        assert!(bool_env_or_default("TEST_BOOL_ENV_GARBAGE", true));
        assert!(!bool_env_or_default("TEST_BOOL_ENV_GARBAGE", false));
        env::remove_var("TEST_BOOL_ENV_GARBAGE");
    }

    /// MCP-1081: validator accepts a 32+ char value.
    #[test]
    fn test_validate_shared_secret_accepts_long_value() {
        let _g = env_lock();
        env::set_var("TEST_VSS_OK", "x".repeat(32));
        assert!(validate_shared_secret_token("TEST_VSS_OK", 32, false, "ctx").is_ok());
        assert!(validate_shared_secret_token("TEST_VSS_OK", 32, true, "ctx").is_ok());
        env::set_var("TEST_VSS_OK", "x".repeat(64));
        assert!(validate_shared_secret_token("TEST_VSS_OK", 32, false, "ctx").is_ok());
        env::remove_var("TEST_VSS_OK");
    }

    /// MCP-1081: validator rejects a too-short value (regardless of required flag).
    #[test]
    fn test_validate_shared_secret_rejects_short_value() {
        let _g = env_lock();
        env::set_var("TEST_VSS_SHORT", "x");
        let err = validate_shared_secret_token("TEST_VSS_SHORT", 32, false, "ctx").unwrap_err();
        assert!(err.contains("TEST_VSS_SHORT"));
        assert!(err.contains("too short"));
        assert!(err.contains("must be >= 32"));
        assert!(err.contains("ctx"));
        // Same outcome whether required or not — short is short.
        assert!(validate_shared_secret_token("TEST_VSS_SHORT", 32, true, "ctx").is_err());
        env::remove_var("TEST_VSS_SHORT");
    }

    /// MCP-1081: empty string treated as unset (consistent with MCP-590/591).
    #[test]
    fn test_validate_shared_secret_empty_treated_as_unset() {
        let _g = env_lock();
        env::set_var("TEST_VSS_EMPTY", "");
        // required=false → empty is OK (request-time gate handles unset).
        assert!(validate_shared_secret_token("TEST_VSS_EMPTY", 32, false, "ctx").is_ok());
        // required=true → empty errors out (says "must be set").
        let err = validate_shared_secret_token("TEST_VSS_EMPTY", 32, true, "ctx").unwrap_err();
        assert!(err.contains("must be set"));
        env::remove_var("TEST_VSS_EMPTY");
    }

    /// MCP-1081: unset env (env var absent entirely).
    #[test]
    fn test_validate_shared_secret_unset() {
        let _g = env_lock();
        env::remove_var("TEST_VSS_UNSET_42");
        // required=false → unset OK.
        assert!(validate_shared_secret_token("TEST_VSS_UNSET_42", 32, false, "ctx").is_ok());
        // required=true → unset errors with "must be set".
        let err = validate_shared_secret_token("TEST_VSS_UNSET_42", 32, true, "ctx").unwrap_err();
        assert!(err.contains("must be set"));
    }

    #[test]
    fn test_smart_memory_context_defaults() {
        let _g = env_lock();
        env::remove_var("ENABLE_SMART_MEMORY_CONTEXT");
        env::remove_var("SMART_MEMORY_CONTEXT_BYTE_BUDGET");
        env::remove_var("SMART_MEMORY_CONTEXT_PER_MEMORY_CAP");
        env::remove_var("SMART_MEMORY_CONTEXT_MIN_SCORE");
        // Flag defaults OFF → legacy byte-identical behaviour.
        assert!(!crate::smart_memory_context_enabled());
        assert_eq!(crate::smart_memory_context_byte_budget(), 12_000);
        assert_eq!(crate::smart_memory_context_per_memory_cap(), 3_000);
        assert!((crate::smart_memory_context_min_score() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_smart_memory_context_overrides_and_guards() {
        let _g = env_lock();
        env::set_var("ENABLE_SMART_MEMORY_CONTEXT", "on");
        assert!(crate::smart_memory_context_enabled());
        // Positive overrides are honoured.
        env::set_var("SMART_MEMORY_CONTEXT_BYTE_BUDGET", "5000");
        assert_eq!(crate::smart_memory_context_byte_budget(), 5_000);
        // =0 collapses to the default (destructive-zero guard).
        env::set_var("SMART_MEMORY_CONTEXT_PER_MEMORY_CAP", "0");
        assert_eq!(crate::smart_memory_context_per_memory_cap(), 3_000);
        // min_score is clamped into [0, 1]; a >1 value clamps to 1.0.
        env::set_var("SMART_MEMORY_CONTEXT_MIN_SCORE", "5.0");
        assert!((crate::smart_memory_context_min_score() - 1.0).abs() < f64::EPSILON);
        env::remove_var("ENABLE_SMART_MEMORY_CONTEXT");
        env::remove_var("SMART_MEMORY_CONTEXT_BYTE_BUDGET");
        env::remove_var("SMART_MEMORY_CONTEXT_PER_MEMORY_CAP");
        env::remove_var("SMART_MEMORY_CONTEXT_MIN_SCORE");
    }

    #[test]
    fn test_smart_memory_context_p2_ranking_defaults() {
        let _g = env_lock();
        for v in [
            "SMART_MEMORY_CONTEXT_W_RELEVANCE",
            "SMART_MEMORY_CONTEXT_W_RECENCY",
            "SMART_MEMORY_CONTEXT_W_IMPORTANCE",
            "SMART_MEMORY_CONTEXT_RECENCY_HALFLIFE_DAYS",
            "SMART_MEMORY_CONTEXT_GRAPH_BASELINE",
            "SMART_MEMORY_CONTEXT_RECENCY_BASELINE",
            "ENABLE_SMART_MEMORY_HYDE",
        ] {
            env::remove_var(v);
        }
        assert!((crate::smart_memory_context_w_relevance() - 1.0).abs() < f64::EPSILON);
        assert!((crate::smart_memory_context_w_recency() - 0.3).abs() < f64::EPSILON);
        assert!((crate::smart_memory_context_w_importance() - 0.5).abs() < f64::EPSILON);
        assert!((crate::smart_memory_context_recency_halflife_days() - 7.0).abs() < f64::EPSILON);
        assert!((crate::smart_memory_context_graph_baseline() - 0.6).abs() < f64::EPSILON);
        assert!((crate::smart_memory_context_recency_baseline() - 0.4).abs() < f64::EPSILON);
        assert!(!crate::smart_memory_hyde_enabled());
    }

    #[test]
    fn test_smart_memory_context_p3a_access_weight() {
        let _g = env_lock();
        env::remove_var("SMART_MEMORY_CONTEXT_ACCESS_WEIGHT");
        // Default.
        assert!((crate::smart_memory_context_access_weight() - 0.15).abs() < f64::EPSILON);
        // Positive override honoured.
        env::set_var("SMART_MEMORY_CONTEXT_ACCESS_WEIGHT", "0.5");
        assert!((crate::smart_memory_context_access_weight() - 0.5).abs() < f64::EPSILON);
        // =0 collapses to the default (destructive-zero guard).
        env::set_var("SMART_MEMORY_CONTEXT_ACCESS_WEIGHT", "0");
        assert!((crate::smart_memory_context_access_weight() - 0.15).abs() < f64::EPSILON);
        // Negative collapses to the default.
        env::set_var("SMART_MEMORY_CONTEXT_ACCESS_WEIGHT", "-1");
        assert!((crate::smart_memory_context_access_weight() - 0.15).abs() < f64::EPSILON);
        // Garbage collapses to the default.
        env::set_var("SMART_MEMORY_CONTEXT_ACCESS_WEIGHT", "not-a-number");
        assert!((crate::smart_memory_context_access_weight() - 0.15).abs() < f64::EPSILON);
        // Above range clamps to 1.0.
        env::set_var("SMART_MEMORY_CONTEXT_ACCESS_WEIGHT", "5.0");
        assert!((crate::smart_memory_context_access_weight() - 1.0).abs() < f64::EPSILON);
        env::remove_var("SMART_MEMORY_CONTEXT_ACCESS_WEIGHT");
    }

    #[test]
    fn test_smart_memory_context_p2_overrides_and_guards() {
        let _g = env_lock();
        // Positive overrides honoured.
        env::set_var("SMART_MEMORY_CONTEXT_W_RECENCY", "2.0");
        assert!((crate::smart_memory_context_w_recency() - 2.0).abs() < f64::EPSILON);
        // =0 collapses to the default (would silently drop the whole signal).
        env::set_var("SMART_MEMORY_CONTEXT_W_IMPORTANCE", "0");
        assert!((crate::smart_memory_context_w_importance() - 0.5).abs() < f64::EPSILON);
        // Half-life of 0 (divide-by-zero) collapses to the default.
        env::set_var("SMART_MEMORY_CONTEXT_RECENCY_HALFLIFE_DAYS", "0");
        assert!((crate::smart_memory_context_recency_halflife_days() - 7.0).abs() < f64::EPSILON);
        // Baselines clamp into [0, 1].
        env::set_var("SMART_MEMORY_CONTEXT_GRAPH_BASELINE", "5.0");
        assert!((crate::smart_memory_context_graph_baseline() - 1.0).abs() < f64::EPSILON);
        // HyDE toggle honours canonical truthy tokens.
        env::set_var("ENABLE_SMART_MEMORY_HYDE", "yes");
        assert!(crate::smart_memory_hyde_enabled());
        for v in [
            "SMART_MEMORY_CONTEXT_W_RECENCY",
            "SMART_MEMORY_CONTEXT_W_IMPORTANCE",
            "SMART_MEMORY_CONTEXT_RECENCY_HALFLIFE_DAYS",
            "SMART_MEMORY_CONTEXT_GRAPH_BASELINE",
            "ENABLE_SMART_MEMORY_HYDE",
        ] {
            env::remove_var(v);
        }
    }

    #[test]
    fn test_is_allowed_origin_matching() {
        let _g = env_lock();
        env::set_var("RUST_ENV", "development");
        env::set_var(
            "ALLOWED_ORIGIN",
            "http://localhost:3000,http://localhost:3001",
        );
        assert!(is_allowed_origin("http://localhost:3000"));
        assert!(is_allowed_origin("http://localhost:3001"));
        assert!(!is_allowed_origin("http://localhost:3002"));
        env::remove_var("RUST_ENV");
        env::remove_var("ALLOWED_ORIGIN");
    }

    #[test]
    fn test_memory_consolidation_config() {
        let _g = env_lock();
        // Master switch defaults OFF; honours canonical truthy tokens.
        for v in [
            "ENABLE_MEMORY_CONSOLIDATION",
            "MEMORY_CONSOLIDATION_TIER1_LOCAL_OK",
            "MEMORY_CONSOLIDATION_INTERVAL_SECS",
            "MEMORY_CONSOLIDATION_MIN_AGE_DAYS",
            "MEMORY_CONSOLIDATION_MAX_IMPORTANCE",
            "MEMORY_CONSOLIDATION_BATCH_SIZE",
            "MEMORY_CONSOLIDATION_MAX_ACTORS_PER_TICK",
            "MEMORY_CONSOLIDATION_MODEL",
        ] {
            env::remove_var(v);
        }
        assert!(!crate::memory_consolidation_enabled());
        assert!(!crate::memory_consolidation_tier1_local_ok());
        env::set_var("ENABLE_MEMORY_CONSOLIDATION", "on");
        assert!(crate::memory_consolidation_enabled());
        env::set_var("MEMORY_CONSOLIDATION_TIER1_LOCAL_OK", "true");
        assert!(crate::memory_consolidation_tier1_local_ok());

        // Numeric defaults.
        assert_eq!(crate::memory_consolidation_interval_secs(), 3600);
        assert!((crate::memory_consolidation_min_age_days() - 30.0).abs() < f64::EPSILON);
        assert!((crate::memory_consolidation_max_importance() - 0.4).abs() < f64::EPSILON);
        assert_eq!(crate::memory_consolidation_batch_size(), 20);
        assert_eq!(crate::memory_consolidation_max_actors_per_tick(), 25);
        assert_eq!(crate::memory_consolidation_model(), "qwen2.5:7b");

        // Destructive-zero / clamp guards.
        env::set_var("MEMORY_CONSOLIDATION_INTERVAL_SECS", "0");
        assert_eq!(crate::memory_consolidation_interval_secs(), 3600);
        env::set_var("MEMORY_CONSOLIDATION_MAX_IMPORTANCE", "5.0");
        assert!((crate::memory_consolidation_max_importance() - 1.0).abs() < f64::EPSILON);
        // Batch size clamps to [3, 100]: below floor and above ceiling.
        env::set_var("MEMORY_CONSOLIDATION_BATCH_SIZE", "1");
        assert_eq!(crate::memory_consolidation_batch_size(), 3);
        env::set_var("MEMORY_CONSOLIDATION_BATCH_SIZE", "1000");
        assert_eq!(crate::memory_consolidation_batch_size(), 100);
        // Actors-per-tick clamps to [1, 500].
        env::set_var("MEMORY_CONSOLIDATION_MAX_ACTORS_PER_TICK", "99999");
        assert_eq!(crate::memory_consolidation_max_actors_per_tick(), 500);
        // Blank model falls back to the default.
        env::set_var("MEMORY_CONSOLIDATION_MODEL", "   ");
        assert_eq!(crate::memory_consolidation_model(), "qwen2.5:7b");
        env::set_var("MEMORY_CONSOLIDATION_MODEL", "llama3.1:8b");
        assert_eq!(crate::memory_consolidation_model(), "llama3.1:8b");

        for v in [
            "ENABLE_MEMORY_CONSOLIDATION",
            "MEMORY_CONSOLIDATION_TIER1_LOCAL_OK",
            "MEMORY_CONSOLIDATION_INTERVAL_SECS",
            "MEMORY_CONSOLIDATION_MAX_IMPORTANCE",
            "MEMORY_CONSOLIDATION_BATCH_SIZE",
            "MEMORY_CONSOLIDATION_MAX_ACTORS_PER_TICK",
            "MEMORY_CONSOLIDATION_MODEL",
        ] {
            env::remove_var(v);
        }
    }
}
