#[cfg(test)]
mod tests {
    use crate::credentials::{is_pg_unique_violation, OAuthCredentialService};
    use crate::revoke_at_provider;

    // ========================================================================
    // revoke_at_provider dispatch tests
    // ========================================================================
    //
    // These tests cover only the branches that don't touch the network. The
    // gmail/google_calendar/slack branches make outbound HTTPS calls — those
    // are exercised by integration tests in staging, not here.

    #[tokio::test]
    async fn revoke_atlassian_returns_no_endpoint_marker() {
        // Atlassian has no public revoke endpoint — the wire-form contract
        // is `Ok(false)` so the caller knows local cleanup is the only path.
        let result = revoke_at_provider("atlassian", "ATATT3xfake")
            .await
            .expect("atlassian must not error");
        assert!(
            !result,
            "atlassian provider must return Ok(false) — no revoke endpoint"
        );
    }

    #[tokio::test]
    async fn revoke_unknown_provider_no_op() {
        // Defensive default — an unrecognised provider must not raise an
        // error or attempt a network call. Caller would log + continue.
        let result = revoke_at_provider("does-not-exist", "ignored")
            .await
            .expect("unknown provider must not error");
        assert!(!result);
    }

    // ========================================================================
    // Key path helper tests
    // ========================================================================

    #[test]
    fn test_access_token_path_format() {
        let user_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = OAuthCredentialService::access_token_path("google", user_id, "primary");
        assert_eq!(
            path,
            "oauth/google/550e8400-e29b-41d4-a716-446655440000/primary/access_token"
        );
    }

    #[test]
    fn test_refresh_token_path_format() {
        let user_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = OAuthCredentialService::refresh_token_path("google", user_id, "primary");
        assert_eq!(
            path,
            "oauth/google/550e8400-e29b-41d4-a716-446655440000/primary/refresh_token"
        );
    }

    #[test]
    fn test_token_paths_differ_only_by_suffix() {
        let user_id = uuid::Uuid::new_v4();
        let access = OAuthCredentialService::access_token_path("github", user_id, "work");
        let refresh = OAuthCredentialService::refresh_token_path("github", user_id, "work");

        assert!(access.ends_with("/access_token"));
        assert!(refresh.ends_with("/refresh_token"));
        assert_ne!(access, refresh);
    }

    #[test]
    fn test_token_paths_with_special_chars_in_provider_key() {
        let user_id = uuid::Uuid::new_v4();
        let path = OAuthCredentialService::access_token_path("custom-provider", user_id, "key_123");
        assert!(path.contains("custom-provider"));
        assert!(path.contains("key_123"));
    }

    // ========================================================================
    // is_pg_unique_violation tests
    // ========================================================================

    #[test]
    fn test_is_pg_unique_violation_with_non_db_error() {
        let err = anyhow::anyhow!("some random error");
        assert!(!is_pg_unique_violation(&err));
    }

    #[test]
    fn test_is_pg_unique_violation_with_anyhow_error() {
        // Create a generic anyhow error - this won't have a sqlx::Error in the chain
        let err = anyhow::anyhow!("test error");
        assert!(!is_pg_unique_violation(&err));
    }
}
