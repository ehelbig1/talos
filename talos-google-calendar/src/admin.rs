//! Admin-only Google Calendar operations.
//!
//! These endpoints bypass the normal session-cookie auth path and
//! operate on behalf of an arbitrary user_id. They exist for operator
//! tooling: the live-test harness (`docs/gcal-live-test.md`), force-
//! stopping a user's runaway channel from the shell, etc.
//!
//! # Defense in depth
//!
//! Every endpoint here is gated by TWO checks:
//!
//! 1. `ENABLE_ADMIN_OPS=1` environment variable — the "big switch".
//!    In production this MUST be unset. A leaked `ADMIN_SECRET_KEY`
//!    alone is not enough to reach these routes.
//!
//! 2. `X-Admin-Secret` header matching `ADMIN_SECRET_KEY`, compared
//!    in constant time to avoid length / byte-position leakage.
//!    Empty `ADMIN_SECRET_KEY` fails closed (every request → 401).
//!
//! Every authorized request writes a row to the shared
//! `google_calendar_audit_log` table with `event_type` prefixed
//! `admin_` so "who did what on whom" is trivially queryable
//! post-incident.
//!
//! End users have self-service paths for the same actions; see the
//! REST handlers in `handlers.rs` and the GraphQL mutations in
//! `api/schema/modules/mutations.rs`.

use super::GoogleCalendarService;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use talos_integration_helpers::admin::{authorize_admin_request, require_uuid_field};
use talos_integration_state::execute_op;
use talos_memory::integration_state_rpc::{IntegrationOp, IntegrationOpResult, ListFilter};
use uuid::Uuid;

/// Envelope-check for every admin-ops request. Returns `Ok(())` on
/// success; on failure the (already-built) rejection response is
/// returned so the caller doesn't re-implement the short-circuit.
///
/// The two-check defense (MCP-1064 canonical `admin_ops_enabled()`
/// "big red button" resolver + MCP-983 direct-slice `ct_eq`, no padded
/// buffer) lives in
/// `talos_integration_helpers::admin::authorize_admin_request` so the
/// gmail/gcal skeletons can't drift and future security fixes land
/// once.
fn authorize(headers: &HeaderMap) -> Result<(), (StatusCode, Json<JsonValue>)> {
    authorize_admin_request(headers, "gcal")
}

/// Audit-log a successful admin action. Every admin endpoint calls
/// this. Insert failure is logged but non-fatal — losing the audit
/// row is a visibility regression, not a correctness one. The
/// MCP-1015 metadata DLP scrub + MCP-1197 measure-first-then-redact
/// bound live in the shared helper; this wrapper pins gcal's
/// historical `admin_{action}` event_type and failure-warn text.
async fn log_admin_action(pool: &sqlx::PgPool, user_id: Uuid, action: &str, metadata: JsonValue) {
    talos_integration_helpers::admin::log_admin_action(
        pool,
        user_id,
        &format!("admin_{action}"),
        action,
        "admin audit log insert failed",
        metadata,
    )
    .await;
}

// ---------------------------------------------------------------------------
// POST /api/admin/google-calendar/watch
// ---------------------------------------------------------------------------
//
// Body: { "integration_id": "<uuid>", "calendar_id": "primary" }
// Response: { "channel_uuid": "...", "google_channel_id": "...", ... }
//
// The webhook URL is derived from BASE_URL; callers cannot redirect it.
pub async fn create_watch(
    State(service): State<Arc<GoogleCalendarService>>,
    headers: HeaderMap,
    Json(body): Json<JsonValue>,
) -> (StatusCode, Json<JsonValue>) {
    if let Err(rejection) = authorize(&headers) {
        return rejection;
    }

    let integration_id = match require_uuid_field(&body, "integration_id") {
        Ok(id) => id,
        Err(rejection) => return rejection,
    };
    let calendar_id = body
        .get("calendar_id")
        .and_then(|v| v.as_str())
        .unwrap_or("primary")
        .to_string();

    // MCP-1155: canonical `get_base_url()` — collapses MCP-653 empty-
    // env handling AND open-redirect-misconfig defense into one
    // helper shared across every BASE_URL site.
    let webhook_url = format!(
        "{}/api/google-calendar/webhook",
        talos_public_url::public_base_url_or(talos_config::get_base_url)
    );

    // Resolve the owning user_id for the audit log. If this SELECT
    // fails the watch-channel call will fail too, so we don't need
    // to gate on it separately.
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM google_calendar_integrations WHERE id = $1")
            .bind(integration_id)
            .fetch_optional(&service.db_pool)
            .await
            .unwrap_or(None);

    match service
        .create_watch_channel(integration_id, &calendar_id, &webhook_url, None)
        .await
    {
        Ok(ch) => {
            if let Some(uid) = owner {
                log_admin_action(
                    &service.db_pool,
                    uid,
                    "watch_created",
                    json!({
                        "integration_id": integration_id,
                        "calendar_id": calendar_id,
                        "channel_uuid": ch.id,
                        "google_channel_id": ch.channel_id,
                    }),
                )
                .await;
            }
            (
                StatusCode::OK,
                Json(json!({
                    "channel_uuid": ch.id,
                    "google_channel_id": ch.channel_id,
                    "calendar_id": ch.calendar_id,
                    "expiration": ch.expiration,
                    "webhook_url": ch.webhook_url,
                })),
            )
        }
        Err(e) => {
            // create_watch_channel failures may carry Google API
            // responses, sqlx errors with table names, or KEK provider
            // details. Log full chain server-side; return generic.
            tracing::error!(
                ?integration_id,
                calendar_id = %calendar_id,
                "gcal admin: create_watch failed: {:#}",
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create Calendar watch. Check controller logs."})),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/google-calendar/stop-orphan
// ---------------------------------------------------------------------------
//
// Body: { "user_id": "<uuid>", "channel_id": "<google_channel_id>",
//         "resource_id": "<google_resource_id>" }
// Response: { "stopped": true }
//
// Tears down a Google-side channel whose integration_state row is
// gone (orphaned — row deletion lost the resource_id we'd need to
// stop through the normal path). Reads the user's access token via
// the canonical credential service, then calls Google's stop API
// directly. No integration_state write because there's nothing to
// write — the whole point is that no row exists.
//
// The (channel_id, resource_id) pair is typically recovered from
// the `google_calendar_audit_log.metadata` of the original
// `channel_created` audit row.
pub async fn stop_orphan(
    State(service): State<Arc<GoogleCalendarService>>,
    headers: HeaderMap,
    Json(body): Json<JsonValue>,
) -> (StatusCode, Json<JsonValue>) {
    if let Err(rejection) = authorize(&headers) {
        return rejection;
    }

    let user_id = match require_uuid_field(&body, "user_id") {
        Ok(id) => id,
        Err(rejection) => return rejection,
    };

    // Length caps on Google-supplied ids. Channel IDs are UUIDs we
    // picked (≤36 chars); resource IDs are Google-assigned opaque
    // strings that have historically been ≤128 chars. 256 is a
    // generous ceiling that keeps this endpoint from being a
    // DoS lever for large-string HMAC / logging work downstream.
    const MAX_ID_LEN: usize = 256;
    let channel_id = match body.get("channel_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() && s.len() <= MAX_ID_LEN => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "channel_id required (non-empty string, ≤256 chars)"})),
            )
        }
    };
    let resource_id = match body.get("resource_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() && s.len() <= MAX_ID_LEN => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "resource_id required (non-empty string, ≤256 chars)"})),
            )
        }
    };

    // Defense-in-depth: verify the (user_id, channel_id) pair exists
    // in our OWN audit log before asking Google to stop the channel.
    // Without this check, any holder of ADMIN_SECRET_KEY could issue
    // stop commands against arbitrary Google channels using this
    // user's OAuth token — cross-tenant interference with no paper
    // trail on our side.
    //
    // Pairs are looked up against audit rows we wrote at create
    // time. If the caller claims a channel we never created for this
    // user, we refuse. For channels created before resource_id was
    // captured in audit metadata (pre-commit 7018372), this check
    // still passes on channel_uuid alone — resource_id is validated
    // by Google's stop API itself.
    let pair_known: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS (\
           SELECT 1 FROM google_calendar_audit_log \
           WHERE user_id = $1 \
             AND event_type = 'channel_created' \
             AND success = true \
             AND metadata->>'google_channel_id' = $2)",
    )
    .bind(user_id)
    .bind(&channel_id)
    .fetch_optional(&service.db_pool)
    .await
    .ok()
    .flatten();
    if !pair_known.unwrap_or(false) {
        tracing::warn!(
            %user_id,
            channel_id = %channel_id,
            "admin stop_orphan rejected: no matching channel_created audit row for this user"
        );
        log_admin_action(
            &service.db_pool,
            user_id,
            "stop_orphan_rejected",
            json!({
                "channel_id": channel_id,
                "reason": "no matching channel_created audit row for this user",
            }),
        )
        .await;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "no audit record of this channel being created for this user"
            })),
        );
    }

    // Pick the caller's first active integration — in a single-
    // integration setup (typical) this is unambiguous. If the user
    // has multiple integrations and the orphan belongs to a specific
    // one, the caller would need to pass integration_id; leaving
    // this as a follow-up since orphan cleanup is rare.
    let integration_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM google_calendar_integrations \
         WHERE user_id = $1 AND is_active = true LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&service.db_pool)
    .await
    .unwrap_or(None);
    let integration_id = match integration_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "no active gcal integration for this user"})),
            )
        }
    };

    let integration = match service.get_integration(user_id, integration_id).await {
        Ok(Some(i)) => i,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "integration not found"})),
            )
        }
    };
    let access_token = match service.get_access_token(&integration).await {
        Ok(t) => t,
        Err(e) => {
            // get_access_token can fail with KEK / vault / OAuth-refresh
            // errors that carry refresh-token paths, vault URLs, or
            // upstream Google response bodies. Log full chain
            // server-side; return generic to the caller.
            tracing::error!(
                user_id = %user_id,
                ?integration_id,
                "gcal admin: get_access_token for orphan-stop failed: {:#}",
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to resolve access token. Check controller logs."})),
            );
        }
    };

    let api = super::api::GoogleCalendarApiClient::new();
    let google_result = api
        .stop_watch(&access_token, &channel_id, &resource_id)
        .await;
    let success = google_result.is_ok();
    let err_msg = google_result.as_ref().err().map(|e| e.to_string());

    log_admin_action(
        &service.db_pool,
        user_id,
        "stop_orphan",
        json!({
            "channel_id": channel_id,
            "resource_id": resource_id,
            "success": success,
            "google_error": err_msg,
        }),
    )
    .await;

    if success {
        (StatusCode::OK, Json(json!({ "stopped": true })))
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "stopped": false, "error": err_msg })),
        )
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/google-calendar/stop-all
// ---------------------------------------------------------------------------
//
// Body: { "user_id": "<uuid>" }
// Response: { "stopped": ["<uuid>", ...] }
//
// Iterates every gcal row in integration_state for the given user,
// calls Google's stop API, removes the row. Safe to re-run.
pub async fn stop_all(
    State(service): State<Arc<GoogleCalendarService>>,
    headers: HeaderMap,
    Json(body): Json<JsonValue>,
) -> (StatusCode, Json<JsonValue>) {
    if let Err(rejection) = authorize(&headers) {
        return rejection;
    }

    let user_id = match require_uuid_field(&body, "user_id") {
        Ok(id) => id,
        Err(rejection) => return rejection,
    };

    // Enumerate rows — decode just enough to find internal UUIDs.
    //
    // MCP-504: mirror the gmail admin fix — pre-fix the `_ => vec![]`
    // arm silently collapsed BOTH genuine DB errors AND result-variant
    // mismatches into "user has no watches to stop." Admin saw
    // `{"stopped": []}` and assumed cleanup completed; actually the
    // list query failed. Split the arms so the DB-error path returns
    // 500 with a clear message, and the unexpected-variant path warns
    // loudly with the variant kind for forensic value.
    let entries = match execute_op(
        &service.db_pool,
        super::watch::GCAL_INTEGRATION_NAME,
        user_id,
        IntegrationOp::List {
            filter: ListFilter::default(),
            limit: 500,
        },
    )
    .await
    {
        Ok(IntegrationOpResult::Entries { entries }) => entries,
        Ok(other) => {
            tracing::warn!(
                %user_id,
                ?other,
                "gcal stop_all: integration_state List returned unexpected variant — treating as empty"
            );
            Vec::new()
        }
        Err(e) => {
            // `IntegrationStateError` lacks Display; use Debug.
            tracing::warn!(
                %user_id,
                error = ?e,
                "gcal stop_all: integration_state List failed — returning 500. Admin should re-try once DB is healthy."
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to enumerate user's Google Calendar watch channels; nothing was stopped",
                })),
            );
        }
    };

    // MCP-881 (2026-05-14): track per-row failures alongside successes.
    // Sibling to the Gmail stop_all fix — same misleading-success-by-
    // omission class. An admin running bulk cleanup on a user with
    // failed Google API calls saw a partial `stopped` list with zero
    // signal about the orphans left behind. Now both `stopped` and
    // `failed` are surfaced in the response and audit-logged.
    let mut stopped = Vec::new();
    let mut failed: Vec<JsonValue> = Vec::new();
    for entry in entries {
        let Ok(v) = serde_json::from_str::<JsonValue>(&entry.value) else {
            continue;
        };
        let Some(id_str) = v.get("id").and_then(|x| x.as_str()) else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(id_str) else {
            continue;
        };
        match service.stop_watch_channel(user_id, id).await {
            Ok(_) => stopped.push(id.to_string()),
            Err(e) => {
                tracing::warn!(
                    %user_id,
                    channel_id = %id,
                    error = %e,
                    "gcal stop_all: stop_watch_channel failed for one row — continuing with remaining channels"
                );
                failed.push(json!({
                    "id": id.to_string(),
                    "error": e.to_string(),
                }));
            }
        }
    }

    log_admin_action(
        &service.db_pool,
        user_id,
        "stop_all",
        json!({
            "stopped_count": stopped.len(),
            "stopped": stopped.clone(),
            "failed_count": failed.len(),
            "failed": failed.clone(),
        }),
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "stopped": stopped,
            "failed": failed,
        })),
    )
}
