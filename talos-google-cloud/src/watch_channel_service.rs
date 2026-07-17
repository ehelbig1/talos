//! User-scoped Google Cloud watch-channel queries used by the REST
//! handlers. Mirrors `talos_gmail::watch_channel_service` — same shape,
//! GCP-specific fields.
//!
//! Single source of truth for the list-view projection: strips the raw
//! `push_token` from the row (it never leaves except once at create
//! time), reconstructs the `push_endpoint` for display, resolves module
//! names in one batched query, and enriches each summary with the most
//! recent renewal/dispatch/push failure via one batched `DISTINCT ON`
//! audit query.

use super::watch::GcpWatchService;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use talos_integration_helpers::{looks_like_oauth_failure, RenewalFailure};
use uuid::Uuid;

#[derive(Serialize, Debug, Clone)]
pub struct GcpWatchSummary {
    pub channel_uuid: Uuid,
    pub integration_id: Uuid,
    pub display_name: String,
    pub expected_sa_email: String,
    /// The public push endpoint Google Pub/Sub POSTs to, reconstructed
    /// from the stored raw token. This is the ONE surface (besides the
    /// create response) where the token is exposed — to the OWNING user
    /// only, so they can copy it into their `gcloud subscriptions
    /// create --push-endpoint=...`.
    pub push_endpoint: String,
    pub module_id: Option<Uuid>,
    pub module_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_push_received: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_failure: Option<RenewalFailure>,
}

/// Reconstruct the public push endpoint for a watch token. Base is the
/// public origin (`FRONTEND_URL`) — `/api/gcp/pubsub/*` is proxied to
/// the controller through the same nginx as the SPA.
pub fn push_endpoint_for(base: &str, token: &str) -> String {
    format!("{}/api/gcp/pubsub/{}", base.trim_end_matches('/'), token)
}

pub async fn list_for_user(
    service: &GcpWatchService,
    user_id: Uuid,
) -> anyhow::Result<Vec<GcpWatchSummary>> {
    let rows = service.list_for_user(user_id).await?;
    if rows.is_empty() {
        return Ok(vec![]);
    }

    let base = talos_public_url::public_base_url_or(talos_config::get_frontend_url);

    // Batched module-name resolution, same defense-in-depth filter
    // (`user_id IS NULL OR user_id = $caller`) as gmail/gcal.
    let module_ids: Vec<Uuid> = rows.iter().filter_map(|r| r.module_id).collect();
    let mut module_name_by_id: HashMap<Uuid, String> = HashMap::new();
    if !module_ids.is_empty() {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
        }
        let db_rows: Vec<Row> = sqlx::query_as(
            "SELECT id, name \
               FROM modules \
              WHERE id = ANY($1) \
                AND (user_id IS NULL OR user_id = $2)",
        )
        .bind(&module_ids)
        .bind(user_id)
        .fetch_all(&service.pool)
        .await
        .unwrap_or_default();
        for row in db_rows {
            module_name_by_id.insert(row.id, row.name);
        }
    }

    let mut summaries: Vec<GcpWatchSummary> = rows
        .into_iter()
        .map(|r| GcpWatchSummary {
            channel_uuid: r.id,
            integration_id: r.integration_id,
            display_name: r.display_name,
            expected_sa_email: r.expected_sa_email,
            push_endpoint: push_endpoint_for(&base, &r.push_token),
            module_id: r.module_id,
            module_name: r
                .module_id
                .and_then(|id| module_name_by_id.get(&id).cloned()),
            last_push_received: r
                .last_push_received_ms
                .and_then(DateTime::<Utc>::from_timestamp_millis),
            created_at: DateTime::<Utc>::from_timestamp_millis(r.created_at_ms)
                .unwrap_or_else(Utc::now),
            recent_failure: None,
        })
        .collect();

    attach_recent_failures(service, user_id, &mut summaries).await;
    Ok(summaries)
}

async fn attach_recent_failures(
    service: &GcpWatchService,
    user_id: Uuid,
    summaries: &mut [GcpWatchSummary],
) {
    if summaries.is_empty() {
        return;
    }
    let channel_uuids: Vec<String> = summaries
        .iter()
        .map(|s| s.channel_uuid.to_string())
        .collect();

    // Latest push-reject / dispatch-failure audit event per channel_uuid
    // in the last 25h. Same DISTINCT ON pattern as gmail/gcal.
    let rows: Vec<(String, String, bool, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT DISTINCT ON (metadata->>'channel_uuid') \
                metadata->>'channel_uuid' AS channel_uuid, \
                event_type, \
                success, \
                error_message, \
                created_at \
         FROM google_calendar_audit_log \
         WHERE user_id = $1 \
           AND event_type IN ('gcp_channel_push_rejected', 'gcp_dispatch_failed') \
           AND metadata->>'channel_uuid' = ANY($2) \
           AND created_at > now() - interval '25 hours' \
         ORDER BY metadata->>'channel_uuid', created_at DESC",
    )
    .bind(user_id)
    .bind(&channel_uuids)
    .fetch_all(&service.pool)
    .await
    .unwrap_or_default();

    let mut latest: HashMap<String, RenewalFailure> = HashMap::new();
    for (cu, _event_type, success, error_message, at) in rows {
        if !success {
            let err = error_message.unwrap_or_else(|| "unknown error".into());
            let likely_oauth_failure = looks_like_oauth_failure(&err);
            latest.insert(
                cu,
                RenewalFailure {
                    error_message: truncate(&err, 300),
                    failed_at: at,
                    likely_oauth_failure,
                },
            );
        }
    }
    for s in summaries.iter_mut() {
        if let Some(f) = latest.remove(&s.channel_uuid.to_string()) {
            s.recent_failure = Some(f);
        }
    }
}

/// Codepoint-safe truncation with an ellipsis marker.
pub(crate) fn truncate(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        s.to_string()
    } else {
        let mut out = s.chars().take(cap).collect::<String>();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_endpoint_reconstruction() {
        assert_eq!(
            push_endpoint_for("https://talos.example.com", "tok-abc"),
            "https://talos.example.com/api/gcp/pubsub/tok-abc"
        );
        // Trailing slash on the base must not double up.
        assert_eq!(
            push_endpoint_for("https://talos.example.com/", "tok-abc"),
            "https://talos.example.com/api/gcp/pubsub/tok-abc"
        );
    }

    #[test]
    fn oauth_classification_passthrough() {
        // The summary service delegates the OAuth-dead heuristic to the
        // shared helper; verify the passthrough classifies the two
        // classes the way the banner logic expects.
        assert!(looks_like_oauth_failure("HTTP 401 Unauthorized"));
        assert!(looks_like_oauth_failure("invalid_grant: token revoked"));
        assert!(!looks_like_oauth_failure("NATS publish failed: timeout"));
    }

    #[test]
    fn truncate_is_codepoint_safe() {
        // Multi-byte codepoints must not be split mid-character.
        let s = "café☕".repeat(200);
        let out = truncate(&s, 10);
        assert!(out.chars().count() <= 11); // 10 + ellipsis
        assert!(out.ends_with('…'));
    }
}
