//! Admin-only Gmail watch operations — parity with gcal's
//! `google_calendar::admin` surface.
//!
//! Same defense-in-depth model: ENABLE_ADMIN_OPS=1 gate + constant-
//! time `X-Admin-Secret` compare. Every successful action writes an
//! `admin_gmail_*` audit row so operator use is traceable.
//!
//! End users have self-service paths (the REST endpoints in
//! handlers.rs, driven by the frontend panel). These endpoints
//! exist for operator tooling: live-test harnesses, bulk cleanup,
//! creating watches on behalf of a user who's hit an edge case.

use super::watch::GmailWatchService;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use talos_integration_helpers::admin::{authorize_admin_request, require_uuid_field};
use uuid::Uuid;

/// Gate every request behind BOTH the big-red-button env var and a
/// constant-time secret compare. Returns `Ok(())` on pass; the
/// pre-built rejection response on fail.
///
/// The two-check defense (MCP-1064 canonical `admin_ops_enabled()`
/// resolver + MCP-983 direct-slice `ct_eq`, no padded buffer) lives in
/// `talos_integration_helpers::admin::authorize_admin_request` so the
/// gmail/gcal skeletons can't drift and future security fixes land
/// once.
fn authorize(headers: &HeaderMap) -> Result<(), (StatusCode, Json<JsonValue>)> {
    authorize_admin_request(headers, "gmail")
}

/// Audit-log a successful admin action. The MCP-1015 metadata DLP
/// scrub + MCP-1197 measure-first-then-redact bound live in the shared
/// helper; this wrapper pins Gmail's historical `admin_gmail_{action}`
/// event_type and failure-warn text.
async fn log_admin_action(pool: &sqlx::PgPool, user_id: Uuid, action: &str, metadata: JsonValue) {
    talos_integration_helpers::admin::log_admin_action(
        pool,
        user_id,
        &format!("admin_gmail_{action}"),
        action,
        "admin gmail audit log insert failed",
        metadata,
    )
    .await;
}

// ---------------------------------------------------------------------------
// POST /api/admin/gmail/watch
// ---------------------------------------------------------------------------
//
// Body: { "user_id": "<uuid>", "integration_id": "<uuid>",
//         "label_ids": ["INBOX"]?, "module_id": "<uuid>"? }
// Response: { channel_uuid, email_address, topic_name, history_id,
//             expiration_ms }
pub async fn create_watch(
    State(service): State<Arc<GmailWatchService>>,
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
    let integration_id = match require_uuid_field(&body, "integration_id") {
        Ok(id) => id,
        Err(rejection) => return rejection,
    };
    let label_ids: Option<Vec<String>> =
        body.get("label_ids").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        });
    let module_id: Option<Uuid> = body
        .get("module_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    match service
        .create_watch(user_id, integration_id, module_id, label_ids)
        .await
    {
        Ok(row) => {
            log_admin_action(
                &service.pool,
                user_id,
                "watch_created",
                json!({
                    "channel_uuid": row.id,
                    "integration_id": integration_id,
                    "email_address": row.email_address,
                    "topic_name": row.topic_name,
                    "label_ids": row.label_ids,
                }),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({
                    "channel_uuid": row.id,
                    "email_address": row.email_address,
                    "topic_name": row.topic_name,
                    "history_id": row.history_id,
                    "expiration_ms": row.expiration_ms,
                })),
            )
        }
        Err(e) => {
            // create_watch failures may carry Gmail API responses,
            // Pub/Sub topic errors, or sqlx errors with table names.
            // Log full chain server-side; return a generic message to
            // the admin caller per the controller-wide error-hygiene
            // rule.
            tracing::error!(
                user_id = %user_id,
                ?integration_id,
                ?module_id,
                "gmail admin: create_watch failed: {:#}",
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create Gmail watch. Check controller logs."})),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/gmail/stop-all
// ---------------------------------------------------------------------------
//
// Body: { "user_id": "<uuid>" }
// Response: { "stopped": ["<uuid>", ...] }
//
// Gmail has at most one watch per mailbox, but a user may have
// multiple gmail integrations (different email accounts). This
// iterates every watch row this user owns and stops each.
//
// Note: no separate `stop_orphan` endpoint — Gmail's model is
// simpler than gcal's. `users.stop` cancels the mailbox's push
// subscription entirely, so if our row is lost but Google still
// publishes, the next watch on that mailbox replaces the old one
// automatically. `stop_all` on the owning user is the admin
// cleanup path.
pub async fn stop_all(
    State(service): State<Arc<GmailWatchService>>,
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

    // MCP-504: pair the `.unwrap_or_default()` zero-fallback with a
    // warn so an operator-triggered "stop all" that hits a DB error
    // doesn't silently report success-with-zero-stopped. Pre-fix the
    // admin would see `{"stopped": []}` and assume "user had no
    // watches" when actually the list query failed.
    let rows = match service.list_for_user(user_id).await {
        Ok(rs) => rs,
        Err(e) => {
            tracing::warn!(
                %user_id,
                error = %e,
                "gmail stop_all: list_for_user failed — returning empty stopped list. Admin should re-try once DB is healthy."
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to enumerate user's Gmail watches; nothing was stopped",
                })),
            );
        }
    };
    // MCP-881 (2026-05-14): track per-row failures alongside successes.
    // Pre-fix `if service.stop_watch(...).await.is_ok()` silently
    // dropped failed-stop rows from the response, so an admin running
    // a bulk-cleanup on a user with 5 watches and 3 Google API quota
    // errors saw `{"stopped": ["w1", "w2"]}` with zero signal that
    // three orphans remained. Bulk admin tooling MUST report what
    // failed alongside what succeeded — same misleading-success-by-
    // omission class as the broader MCP-872..880 observability sweep.
    let mut stopped = Vec::new();
    let mut failed: Vec<JsonValue> = Vec::new();
    for row in rows {
        match service.stop_watch(user_id, row.id).await {
            Ok(()) => stopped.push(row.id.to_string()),
            Err(e) => {
                tracing::warn!(
                    %user_id,
                    watch_id = %row.id,
                    error = %e,
                    "gmail stop_all: stop_watch failed for one row — continuing with remaining watches"
                );
                failed.push(json!({
                    "id": row.id.to_string(),
                    "error": e.to_string(),
                }));
            }
        }
    }

    log_admin_action(
        &service.pool,
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
