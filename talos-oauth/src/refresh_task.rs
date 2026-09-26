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
/// Most credentials refreshed per tick (each is one token-endpoint round trip
/// with a 15 s timeout, run serially).
const REFRESH_BATCH_MAX: i64 = 100;

pub async fn proactive_token_refresh_task(cred_service: Arc<OAuthCredentialService>) {
    let mut ticker = interval(Duration::from_secs(300)); // 5 minutes

    loop {
        ticker.tick().await;

        // Query for tokens expiring within REFRESH_THRESHOLD_MINUTES that have a refresh path.
        // The tick interval is 5 minutes and the inner threshold is REFRESH_THRESHOLD_MINUTES,
        // giving headroom before any token actually expires.
        let threshold_mins = super::REFRESH_THRESHOLD_MINUTES as i32;
        // Revoked grants (`needs_reauth_at`) are skipped until re-linked; the
        // batch is bounded, soonest expiry first, so a backlog drains over
        // successive ticks instead of one unbounded pass.
        let expiring: Vec<String> = match sqlx::query_scalar(
            "SELECT access_token_secret_path FROM integration_credentials \
             WHERE is_active = TRUE \
               AND needs_reauth_at IS NULL \
               AND token_expires_at IS NOT NULL \
               AND token_expires_at < NOW() + make_interval(mins => $1::int) \
               AND access_token_secret_path IS NOT NULL \
             ORDER BY token_expires_at, id \
             LIMIT $2",
        )
        .bind(threshold_mins)
        .bind(REFRESH_BATCH_MAX)
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
            let redacted_path = talos_workflow_job_protocol::redact_vault_path_for_log(path);
            match cred_service.refresh_oauth_token_if_needed(path).await {
                Ok(true) => tracing::info!(path = %redacted_path, "Token refresh task: refreshed"),
                Ok(false) => {
                    tracing::debug!(path = %redacted_path, "Token refresh task: still valid")
                }
                Err(e) => {
                    tracing::warn!(path = %redacted_path, error = %e, "Token refresh task: refresh failed")
                }
            }
        }
    }
}

// The path/provider-key redactors that lived here as `pub(crate)` helpers
// (MCP-988, 2026-05-15) moved to `talos_workflow_job_protocol::
// {redact_vault_path_for_log, redact_oauth_provider_key_for_log}` on
// 2026-09-13: the worker's `AuditingProvider` logs the same paths on every
// secret resolve and could not reach a helper private to this crate. Their
// tests moved with them (`vault_path_log_redaction_tests`).
