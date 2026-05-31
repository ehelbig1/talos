use std::sync::Arc;
use tokio::time::{interval, Duration};

use super::OAuthCredentialService;

/// Background task that proactively refreshes OAuth tokens nearing expiry.
///
/// Runs every 5 minutes, queries `integration_credentials` for active tokens
/// whose expiry is within the task's lookahead window, and calls
/// `refresh_oauth_token_if_needed` for each. This prevents token expiry
/// during workflow execution windows.
///
/// IMPORTANT — window invariant: the lookahead here must match (or be no
/// wider than) `refresh_oauth_token_if_needed`'s internal threshold in
/// `oauth/credentials.rs`. If the query returns tokens the inner check won't
/// act on, there's a dead zone where the task does nothing and the token
/// eventually expires. Currently both sides use 10 minutes.
pub async fn proactive_token_refresh_task(cred_service: Arc<OAuthCredentialService>) {
    let mut ticker = interval(Duration::from_secs(300)); // 5 minutes

    loop {
        ticker.tick().await;

        // Query for tokens expiring within REFRESH_THRESHOLD_MINUTES that have a refresh path.
        // The tick interval is 5 minutes and the inner threshold is REFRESH_THRESHOLD_MINUTES,
        // giving headroom before any token actually expires.
        let threshold_mins = super::REFRESH_THRESHOLD_MINUTES as i32;
        let expiring: Vec<String> = match sqlx::query_scalar(
            "SELECT access_token_secret_path FROM integration_credentials \
             WHERE is_active = TRUE \
               AND token_expires_at IS NOT NULL \
               AND token_expires_at < NOW() + make_interval(mins => $1::int) \
               AND access_token_secret_path IS NOT NULL",
        )
        .bind(threshold_mins)
        .fetch_all(cred_service.db_pool())
        .await
        {
            Ok(paths) => paths,
            Err(e) => {
                tracing::warn!(error = %e, "Token refresh task: failed to query expiring tokens");
                continue;
            }
        };

        if expiring.is_empty() {
            tracing::debug!("Token refresh task: no tokens expiring soon");
            continue;
        }

        tracing::info!(
            count = expiring.len(),
            "Token refresh task: refreshing expiring tokens"
        );

        for path in &expiring {
            // MCP-988 (2026-05-15): redact the provider_key (4th path
            // component) before logging. The OAuth vault path shape is
            // `oauth/<provider>/<user_id>/<provider_key>/access_token`
            // (see `OAuthCredentialService::access_token_path`). For
            // `gmail` and `google_calendar` providers, `provider_key`
            // IS the user's email — straight PII. Pre-fix this path
            // was logged at INFO level on every successful refresh,
            // surfacing every active user's email to operator log
            // pipelines on every 5-minute tick. For ~100 users with
            // tokens nearing expiry, that's hundreds of email
            // emissions per cycle. `provider_key` is kept hashed
            // (sha256, 8-hex prefix) so operators can correlate
            // refreshes for the same credential without leaking the
            // raw identifier; the user_id stays visible because it's
            // already a UUID (not directly attributable PII).
            let redacted_path = redact_oauth_path_for_log(path);
            match cred_service.refresh_oauth_token_if_needed(path).await {
                Ok(true) => tracing::info!(path = %redacted_path, "Token refresh task: refreshed"),
                Ok(false) => tracing::debug!(path = %redacted_path, "Token refresh task: still valid"),
                Err(e) => {
                    tracing::warn!(path = %redacted_path, error = %e, "Token refresh task: refresh failed")
                }
            }
        }
    }
}

/// Replace the `provider_key` segment (4th path component) of an OAuth
/// vault path with a sha256 prefix so it's safe for INFO-level logs.
///
/// `oauth/gmail/<user_id>/alice@example.com/access_token`
///   → `oauth/gmail/<user_id>/<a1b2c3d4>/access_token`
///
/// Non-conforming paths return unchanged — the OAuth refresh task
/// only enqueues paths it queried by shape, so this defensive branch
/// is unreachable in practice but doesn't lose information if the
/// shape ever changes.
fn redact_oauth_path_for_log(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() == 5 && parts[0] == "oauth" && parts[4] == "access_token" {
        let hash = Sha256::digest(parts[3].as_bytes());
        let prefix: String = hex::encode(hash).chars().take(8).collect();
        format!(
            "{}/{}/{}/<{}>/{}",
            parts[0], parts[1], parts[2], prefix, parts[4]
        )
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod redact_tests {
    use super::redact_oauth_path_for_log;

    #[test]
    fn redacts_gmail_email() {
        let in_path =
            "oauth/gmail/11111111-2222-3333-4444-555555555555/alice@example.com/access_token";
        let out = redact_oauth_path_for_log(in_path);
        assert!(!out.contains("alice"));
        assert!(!out.contains("example.com"));
        assert!(out.contains("11111111-2222-3333-4444-555555555555"));
        assert!(out.starts_with("oauth/gmail/"));
        assert!(out.ends_with("/access_token"));
    }

    #[test]
    fn passes_through_unexpected_shapes() {
        // Refresh task only enqueues 5-part oauth paths, so any
        // other shape is a future change — fall through unchanged
        // rather than munge it.
        let other = "weird/three/parts";
        assert_eq!(redact_oauth_path_for_log(other), other);
    }

    #[test]
    fn stable_hash_for_same_input() {
        let a = redact_oauth_path_for_log(
            "oauth/atlassian/00000000-0000-0000-0000-000000000000/site-abc/access_token",
        );
        let b = redact_oauth_path_for_log(
            "oauth/atlassian/00000000-0000-0000-0000-000000000000/site-abc/access_token",
        );
        assert_eq!(a, b, "same provider_key must hash to same prefix");
    }

    #[test]
    fn distinct_hashes_for_distinct_keys() {
        let a = redact_oauth_path_for_log(
            "oauth/gmail/00000000-0000-0000-0000-000000000000/alice@example.com/access_token",
        );
        let b = redact_oauth_path_for_log(
            "oauth/gmail/00000000-0000-0000-0000-000000000000/bob@example.com/access_token",
        );
        assert_ne!(a, b, "different provider_keys must produce different log strings");
    }
}
