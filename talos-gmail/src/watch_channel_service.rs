//! User-scoped Gmail watch-channel queries used by the REST
//! handlers. Mirrors gcal's watch_channel_service — same shape,
//! Gmail-specific fields.

use super::watch::GmailWatchService;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use talos_integration_helpers::{looks_like_oauth_failure, RenewalFailure};
use talos_push_channel_inventory::{
    classify_module_binding, ModuleBinding, PushChannelFailure, PushChannelInventory,
    PushChannelRow,
};
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
    /// FOUR-VALUED, and new on 2026-09-08. Until then this surface resolved
    /// module names with `.unwrap_or_default()`, so a database failure and
    /// "the module is gone" both rendered `module_name: null` — the exact
    /// collapse `classify_module_binding` was written for one integration
    /// over, and the reason a dead binding was invisible for weeks. The
    /// variants live in `talos_push_channel_inventory`.
    pub module_binding: ModuleBinding,
    pub workflow_id: Option<Uuid>,
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

    // CLASSIFIED, not defaulted. The pre-2026-09-08 read ended in
    // `.unwrap_or_default()`, so a pool timeout and a deleted module produced
    // the same `module_name: null`. The predicate has ONE home in
    // `talos_registry::module_visibility`, pinned equal to the one the DISPATCH
    // load applies, so this surface and the thing it reports on answer with one
    // rule.
    let module_ids: Vec<Uuid> = rows.iter().filter_map(|r| r.module_id).collect();
    let module_names = talos_registry::module_visibility::visible_module_names(
        &service.pool,
        &module_ids,
        user_id,
    )
    .await;
    if let Err(ref e) = module_names {
        tracing::warn!(
            %user_id,
            error = %e,
            "gmail watch summary: module-name lookup failed; \
             module_binding reported as unreadable"
        );
    }
    let module_name_by_id: HashMap<Uuid, String> =
        module_names.as_ref().cloned().unwrap_or_default();

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
            module_binding: classify_module_binding(r.module_id, &module_names),
            workflow_id: r.workflow_id,
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
    let mut latest = latest_channel_failures(&service.pool, user_id, &channel_uuids).await;
    for s in summaries.iter_mut() {
        if let Some(f) = latest.remove(&s.channel_uuid.to_string()) {
            s.recent_failure = Some(f);
        }
    }
}

/// Latest gmail renewal audit event per `channel_uuid` in the last 25 h; a
/// failure only when the NEWEST event is a failure. ONE home for the query,
/// shared by the owner-facing REST summary and the operator-report inventory —
/// two windows or two event-type lists would make the same channel look failing
/// on one surface and healthy on the other.
async fn latest_channel_failures(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    channel_uuids: &[String],
) -> HashMap<String, RenewalFailure> {
    // Same DISTINCT ON pattern as gcal.
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
    .bind(channel_uuids)
    .fetch_all(pool)
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
    latest
}

/// The operator-report view of this integration's push channels.
///
/// Holds a `PgPool` and nothing else — see `GcpPushChannelInventory` for why
/// (it must be constructible without the OAuth handle or the create-lock map,
/// and it must not be usable to create a watch).
pub struct GmailPushChannelInventory {
    pool: sqlx::PgPool,
}

impl GmailPushChannelInventory {
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl PushChannelInventory for GmailPushChannelInventory {
    fn integration_name(&self) -> &'static str {
        super::watch::GMAIL_INTEGRATION_NAME
    }

    async fn list_channels(&self, user_id: Uuid) -> anyhow::Result<Vec<PushChannelRow>> {
        let rows = super::watch::list_rows_for_user(&self.pool, user_id).await?;
        if rows.is_empty() {
            return Ok(vec![]);
        }
        let module_ids: Vec<Uuid> = rows.iter().filter_map(|r| r.module_id).collect();
        let module_names = talos_registry::module_visibility::visible_module_names(
            &self.pool,
            &module_ids,
            user_id,
        )
        .await;
        if let Err(ref e) = module_names {
            tracing::warn!(
                %user_id,
                error = %e,
                "gmail push-channel inventory: module lookup failed; \
                 bindings reported as unreadable"
            );
        }
        let names = module_names.as_ref().cloned().unwrap_or_default();

        let mut out: Vec<PushChannelRow> = rows
            .into_iter()
            .map(|r| {
                let binding = classify_module_binding(r.module_id, &module_names);
                PushChannelRow {
                    integration: super::watch::GMAIL_INTEGRATION_NAME,
                    channel_id: r.id,
                    // Gmail's watch has no operator-chosen display name; the
                    // mailbox IS the identity, and it is already visible to the
                    // owning user on every other Gmail surface.
                    display_name: r.email_address,
                    module_id: r.module_id,
                    module_name: (binding == ModuleBinding::Bound)
                        .then(|| r.module_id.and_then(|id| names.get(&id).cloned()))
                        .flatten(),
                    module_binding: binding,
                    created_at: DateTime::<Utc>::from_timestamp_millis(r.created_at_ms),
                    last_event_at: DateTime::<Utc>::from_timestamp_millis(r.updated_at_ms),
                    recent_failure: None,
                }
            })
            .collect();

        attach_recent_failures_to_rows(&self.pool, user_id, &mut out).await;
        Ok(out)
    }
}

/// The `DISTINCT ON (channel_uuid)` renewal-failure enrichment, over the
/// operator-report row shape. Shares [`latest_channel_failures`] with the
/// owner-facing summary so the two cannot look back over different windows.
async fn attach_recent_failures_to_rows(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    rows: &mut [PushChannelRow],
) {
    if rows.is_empty() {
        return;
    }
    let ids: Vec<String> = rows.iter().map(|r| r.channel_id.to_string()).collect();
    let mut latest = latest_channel_failures(pool, user_id, &ids).await;
    for r in rows.iter_mut() {
        if let Some(f) = latest.remove(&r.channel_id.to_string()) {
            r.recent_failure = Some(PushChannelFailure {
                likely_oauth_failure: f.likely_oauth_failure,
                error_message: f.error_message,
                failed_at: f.failed_at,
            });
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
