//! User-scoped Gmail watch-channel queries used by the REST
//! handlers. Mirrors gcal's watch_channel_service — same shape,
//! Gmail-specific fields.

use super::watch::GmailWatchService;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use talos_integration_helpers::{looks_like_oauth_failure, RenewalFailure};
use uuid::Uuid;

#[derive(Serialize, Debug, Clone)]
pub struct GmailWatchSummary {
    pub channel_uuid: Uuid,
    pub integration_id: Uuid,
    pub email_address: String,
    pub topic_name: String,
    pub history_id: u64,
    pub label_ids: Vec<String>,
    pub expiration: DateTime<Utc>,
    pub module_id: Option<Uuid>,
    pub module_name: Option<String>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_failure: Option<RenewalFailure>,
}

pub async fn list_for_user(
    service: &GmailWatchService,
    user_id: Uuid,
) -> anyhow::Result<Vec<GmailWatchSummary>> {
    let rows = service.list_for_user(user_id).await?;
    if rows.is_empty() {
        return Ok(vec![]);
    }

    // Batched module-name resolution, same defense-in-depth filter
    // pattern as gcal.
    let module_ids: Vec<Uuid> = rows.iter().filter_map(|r| r.module_id).collect();
    let mut module_name_by_id: HashMap<Uuid, String> = HashMap::new();
    if !module_ids.is_empty() {
        // Phase 5.1: resolve via the unified `modules` table by canonical id.
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

    // Project to API shape.
    let mut summaries: Vec<GmailWatchSummary> = rows
        .into_iter()
        .map(|r| GmailWatchSummary {
            channel_uuid: r.id,
            integration_id: r.integration_id,
            email_address: r.email_address,
            topic_name: r.topic_name,
            history_id: r.history_id,
            label_ids: r.label_ids,
            expiration: DateTime::<Utc>::from_timestamp_millis(r.expiration_ms)
                .unwrap_or_else(Utc::now),
            module_id: r.module_id,
            module_name: r
                .module_id
                .and_then(|id| module_name_by_id.get(&id).cloned()),
            updated_at: DateTime::<Utc>::from_timestamp_millis(r.updated_at_ms)
                .unwrap_or_else(Utc::now),
            recent_failure: None,
        })
        .collect();

    attach_recent_failures(service, user_id, &mut summaries).await;
    Ok(summaries)
}

async fn attach_recent_failures(
    service: &GmailWatchService,
    user_id: Uuid,
    summaries: &mut [GmailWatchSummary],
) {
    if summaries.is_empty() {
        return;
    }
    let channel_uuids: Vec<String> = summaries
        .iter()
        .map(|s| s.channel_uuid.to_string())
        .collect();

    // Same DISTINCT ON pattern as gcal — latest gmail renewal audit
    // event per channel_uuid; flag as failure only if the newest
    // event is a failure.
    let rows: Vec<(String, String, bool, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT DISTINCT ON (metadata->>'channel_uuid') \
                metadata->>'channel_uuid' AS channel_uuid, \
                event_type, \
                success, \
                error_message, \
                created_at \
         FROM google_calendar_audit_log \
         WHERE user_id = $1 \
           AND event_type IN ('gmail_channel_renewed', 'gmail_channel_renewal_failed') \
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

/// MCP-556: was `fn truncate` (private) but `api.rs::tests` referenced
/// it via `use super::*` and could not see it cross-module — the lib
/// test build failed with E0425. Promoted to `pub(crate)` so the
/// orphaned tests resolve. The function is otherwise unchanged; the
/// codepoint-safe `chars().take(cap)` walk continues to be the
/// truncation path used by `summarise_renewal_failures`.
pub(crate) fn truncate(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        s.to_string()
    } else {
        let mut out = s.chars().take(cap).collect::<String>();
        out.push('…');
        out
    }
}
