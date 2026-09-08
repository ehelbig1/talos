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
// The four binding states and the ONE decision about them moved to
// `talos-push-channel-inventory` (2026-09-08) so the operator surfaces — which
// must not depend on this crate — can read the same classification the REST
// list renders. This crate keeps the projection; the leaf crate keeps the rule.
use talos_push_channel_inventory::{
    classify_module_binding, ModuleBinding, PushChannelFailure, PushChannelInventory,
    PushChannelRow,
};
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
    /// FOUR-VALUED — because `module_name: null` is not one state, and
    /// until 2026-09-07 they were rendered identically. The variants and the
    /// classifier live in `talos_push_channel_inventory`; the four wire
    /// spellings below are unchanged and pinned there.
    ///
    /// * `none`       — the watch binds no module; a push is acked and
    ///                  nothing is dispatched. Deliberate configuration.
    /// * `bound`      — the module exists for this user and will load.
    /// * `missing`    — `module_id` is set and names no module this user
    ///                  can load. **Every push to this channel fails.**
    ///                  Measured live on this fleet the day this field
    ///                  was added: the one bound channel on the platform
    ///                  was in exactly this state and had been since it
    ///                  was created.
    /// * `unreadable` — the name lookup ITSELF failed. Not a claim about
    ///                  the binding: `missing` here would be a
    ///                  determinate negative over a query that did not
    ///                  answer (checks 74 / 79's class), and this read
    ///                  used to be `.unwrap_or_default()`, which
    ///                  produced precisely that.
    pub module_binding: ModuleBinding,
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
    // CLASSIFIED, not defaulted. `Ok(map)` — a definite answer, so an id
    // absent from the map really is a module this user cannot load;
    // `Err` — we could not look, and no claim about any binding is
    // available. The predicate has ONE home in
    // `talos_registry::module_visibility`, which pins it equal to the one the
    // DISPATCH load applies (`ModuleRegistry::get_module`) — this surface and
    // the thing it reports on answer with one rule.
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
            "gcp watch summary: module-name lookup failed; \
             module_binding reported as unreadable"
        );
    }
    // The `Result` itself is what the classifier reads — see
    // `classify_module_binding`'s doc for why it is not flattened here.
    let module_name_by_id: HashMap<Uuid, String> =
        module_names.as_ref().cloned().unwrap_or_default();

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
            module_binding: classify_module_binding(r.module_id, &module_names),
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
    let mut latest = latest_channel_failures(&service.pool, user_id, &channel_uuids).await;
    for s in summaries.iter_mut() {
        if let Some(f) = latest.remove(&s.channel_uuid.to_string()) {
            s.recent_failure = Some(f);
        }
    }
}

/// Latest push-reject / dispatch-failure audit event per `channel_uuid` in the
/// last 25 h. ONE home for the query, shared by the owner-facing REST summary
/// and the operator-report inventory — two windows or two event-type lists
/// would make the same channel look failing on one surface and healthy on the
/// other.
async fn latest_channel_failures(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    channel_uuids: &[String],
) -> HashMap<String, RenewalFailure> {
    // Same DISTINCT ON pattern as gmail/gcal.
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
/// Holds a `PgPool` and nothing else — deliberately NOT a `GcpWatchService`,
/// which carries the OAuth integration handle and a create-lock map. Two
/// consequences, both wanted: the inventory can be constructed unconditionally
/// (a channel ROW survives `GCP_PUBSUB_AUDIENCE` being unset, and an operator
/// asking "what push channels do I have?" must still be told about it), and it
/// cannot be used to create a watch, so it can never race the create lock.
pub struct GcpPushChannelInventory {
    pool: sqlx::PgPool,
}

impl GcpPushChannelInventory {
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl PushChannelInventory for GcpPushChannelInventory {
    fn integration_name(&self) -> &'static str {
        super::watch::GOOGLE_CLOUD_INTEGRATION_NAME
    }

    async fn list_channels(&self, user_id: Uuid) -> anyhow::Result<Vec<PushChannelRow>> {
        let rows = super::watch::list_rows_for_user(&self.pool, user_id).await?;
        if rows.is_empty() {
            return Ok(vec![]);
        }
        let module_ids: Vec<Uuid> = rows.iter().filter_map(|r| r.module_id).collect();
        // Same classified read the REST list uses — see `list_for_user`.
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
                "gcp push-channel inventory: module lookup failed; \
                 bindings reported as unreadable"
            );
        }
        let names = module_names.as_ref().cloned().unwrap_or_default();

        let mut out: Vec<PushChannelRow> = rows
            .into_iter()
            .map(|r| {
                let binding = classify_module_binding(r.module_id, &module_names);
                PushChannelRow {
                    integration: super::watch::GOOGLE_CLOUD_INTEGRATION_NAME,
                    channel_id: r.id,
                    display_name: r.display_name,
                    module_id: r.module_id,
                    // A name only for a binding we actually resolved — a name
                    // beside `missing` would be a fabrication.
                    module_name: (binding == ModuleBinding::Bound)
                        .then(|| r.module_id.and_then(|id| names.get(&id).cloned()))
                        .flatten(),
                    module_binding: binding,
                    created_at: DateTime::<Utc>::from_timestamp_millis(r.created_at_ms),
                    last_event_at: r
                        .last_push_received_ms
                        .and_then(DateTime::<Utc>::from_timestamp_millis),
                    recent_failure: None,
                }
            })
            .collect();

        attach_recent_failures_to_rows(&self.pool, user_id, &mut out).await;
        Ok(out)
    }
}

/// The `DISTINCT ON (channel_uuid)` failure enrichment, over the operator-report
/// row shape. Shares the query text with [`attach_recent_failures`] via
/// [`latest_channel_failures`] so the two cannot look back over different
/// windows or different event types.
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
