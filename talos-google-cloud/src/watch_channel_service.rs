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
    /// THREE-VALUED, plus the no-binding case — because `module_name:
    /// null` is not one state but three, and until 2026-09-07 they were
    /// rendered identically.
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
    pub module_binding: &'static str,
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
    // available. The predicate is deliberately the same
    // `id = $1 AND (user_id IS NULL OR user_id = $2)` the DISPATCH load
    // applies (`ModuleRegistry::get_module`), so this surface and the
    // thing it reports on answer with one rule.
    let module_names: Result<HashMap<Uuid, String>, sqlx::Error> = if module_ids.is_empty() {
        Ok(HashMap::new())
    } else {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
        }
        sqlx::query_as::<_, Row>(
            "SELECT id, name \
               FROM modules \
              WHERE id = ANY($1) \
                AND (user_id IS NULL OR user_id = $2)",
        )
        .bind(&module_ids)
        .bind(user_id)
        .fetch_all(&service.pool)
        .await
        .map(|db_rows| db_rows.into_iter().map(|r| (r.id, r.name)).collect())
    };
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

/// The one place the four binding states are decided, so the REST list
/// and any future reader cannot disagree about what a `null`
/// `module_name` means.
///
/// It takes the LOOKUP'S OWN `Result`, not a pre-flattened `Option`, and
/// that is structural rather than stylistic. With an `Option` parameter
/// the classifier is perfectly correct and the CALL SITE can still hand
/// it `Some(HashMap::new())` on an `Err` — a one-line revert to the
/// pre-fix `.unwrap_or_default()` behaviour that every test here
/// SURVIVES (measured 2026-09-07: mutation M-V1d). Reading the `Result`
/// makes that collapse take a deliberate rewrite of the read instead of
/// a defaulted argument. It does not make it impossible; checks 74b and
/// 79b both state that a guard at the read cannot see an answer computed
/// correctly and then discarded.
pub fn classify_module_binding<E>(
    module_id: Option<Uuid>,
    names: &Result<HashMap<Uuid, String>, E>,
) -> &'static str {
    match (module_id, names) {
        (None, _) => "none",
        (Some(_), Err(_)) => "unreadable",
        (Some(id), Ok(map)) => {
            if map.contains_key(&id) {
                "bound"
            } else {
                "missing"
            }
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

    /// A `module_name` of `null` is not one state. Before 2026-09-07 the
    /// three below rendered identically, and the live fleet's one bound
    /// channel was in the `missing` one — every push to it failing, and
    /// no field anywhere saying so.
    #[test]
    fn module_binding_is_three_valued_plus_unbound() {
        let id = Uuid::new_v4();
        let mut map = HashMap::new();
        map.insert(id, "GCP: Alert Normalize".to_string());
        let known: Result<HashMap<Uuid, String>, &str> = Ok(map);
        let unreadable: Result<HashMap<Uuid, String>, &str> = Err("pool timeout");

        assert_eq!(classify_module_binding(None, &known), "none");
        assert_eq!(classify_module_binding(Some(id), &known), "bound");
        // Set, and absent from a map the query DID answer.
        assert_eq!(
            classify_module_binding(Some(Uuid::new_v4()), &known),
            "missing"
        );
        // The query did not answer. Reporting `missing` here would be a
        // determinate negative over a read that failed — which is exactly
        // what the pre-fix `.unwrap_or_default()` produced.
        assert_eq!(classify_module_binding(Some(id), &unreadable), "unreadable");
        // …and an unreadable lookup must NOT claim the unbound case away
        // either: no binding is still no binding.
        assert_eq!(classify_module_binding(None, &unreadable), "none");
        // An EMPTY but ANSWERED map is `missing`, not `unreadable` — the
        // two must not be collapsed in either direction.
        let empty: Result<HashMap<Uuid, String>, &str> = Ok(HashMap::new());
        assert_eq!(classify_module_binding(Some(id), &empty), "missing");
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
