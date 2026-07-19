//! Admin-only Google Cloud watch operations — parity with the
//! gmail/gcal admin surfaces.
//!
//! Same two-gate defense (ENABLE_ADMIN_OPS=1 + constant-time
//! `X-Admin-Secret`, both in `talos_integration_helpers::admin`). Every
//! successful action writes an `admin_gcp_*` audit row.
//!
//! End users have self-service paths (the REST endpoints in handlers.rs
//! driven by the frontend panel). These endpoints exist for operator
//! tooling: live-test harnesses, bulk cleanup, creating a watch on
//! behalf of a user who's hit an edge case.
//!
//! Unlike gcal, there is NO `stop_orphan` endpoint — the user owns the
//! Pub/Sub subscription upstream, so there is no orphaned Google-side
//! resource for us to cancel; deleting our row is the whole cleanup.

use super::watch::GcpWatchService;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use talos_integration_helpers::admin::{authorize_admin_request, require_uuid_field};
use talos_integration_helpers::api_json::ApiJson;
use uuid::Uuid;

/// Gate every request behind the shared two-check defense. The
/// implementation (MCP-1064 `admin_ops_enabled()` + MCP-983 direct-slice
/// `ct_eq`) lives in the helper so this can't drift from gmail/gcal.
fn authorize(headers: &HeaderMap) -> Result<(), (StatusCode, Json<JsonValue>)> {
    authorize_admin_request(headers, "gcp")
}

/// Audit-log a successful admin action. The MCP-1015 DLP scrub +
/// MCP-1197 size bound live in the shared helper; this pins GCP's
/// historical `admin_gcp_{action}` event_type + failure-warn text.
async fn log_admin_action(pool: &sqlx::PgPool, user_id: Uuid, action: &str, metadata: JsonValue) {
    talos_integration_helpers::admin::log_admin_action(
        pool,
        user_id,
        &format!("admin_gcp_{action}"),
        action,
        "admin gcp audit log insert failed",
        metadata,
    )
    .await;
}

// ---------------------------------------------------------------------------
// POST /api/admin/gcp/watch
// ---------------------------------------------------------------------------
//
// Body: { "user_id": "<uuid>", "integration_id": "<uuid>",
//         "expected_sa_email": "<sa email>",
//         "display_name": "<str>"?, "module_id": "<uuid>"? }
// Response: { channel_uuid, integration_id, expected_sa_email }
pub async fn create_watch(
    State(service): State<Arc<GcpWatchService>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<JsonValue>,
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
    let expected_sa_email = match body.get("expected_sa_email").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "expected_sa_email required (string)"})),
            );
        }
    };
    let display_name: Option<String> = body
        .get("display_name")
        .and_then(|v| v.as_str())
        .map(String::from);
    let module_id: Option<Uuid> = body
        .get("module_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    match service
        .create_watch(
            user_id,
            integration_id,
            expected_sa_email,
            display_name,
            module_id,
        )
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
                    "expected_sa_email": row.expected_sa_email,
                }),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({
                    "channel_uuid": row.id,
                    "integration_id": row.integration_id,
                    "expected_sa_email": row.expected_sa_email,
                })),
            )
        }
        Err(e) => {
            // create_watch failures carry SA-validation / integration-
            // lookup / sqlx detail. Log full chain server-side; return a
            // generic message to the admin caller.
            tracing::error!(
                user_id = %user_id,
                ?integration_id,
                "gcp admin: create_watch failed: {:#}",
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create GCP watch. Check controller logs."})),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/gcp/stop-all
// ---------------------------------------------------------------------------
//
// Body: { "user_id": "<uuid>" }
// Response: { "stopped": ["<uuid>", ...], "failed": [ ... ] }
//
// Stops every google_cloud watch this user owns. No `stop_orphan`
// analogue — the user owns the upstream subscription.
pub async fn stop_all(
    State(service): State<Arc<GcpWatchService>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<JsonValue>,
) -> (StatusCode, Json<JsonValue>) {
    if let Err(rejection) = authorize(&headers) {
        return rejection;
    }

    let user_id = match require_uuid_field(&body, "user_id") {
        Ok(id) => id,
        Err(rejection) => return rejection,
    };

    // MCP-504: pair the empty-list fallback with a warn so a DB error
    // doesn't silently report success-with-zero-stopped.
    let rows = match service.list_for_user(user_id).await {
        Ok(rs) => rs,
        Err(e) => {
            tracing::warn!(
                %user_id,
                error = %e,
                "gcp stop_all: list_for_user failed — returning error. Admin should re-try once DB is healthy."
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to enumerate user's GCP watches; nothing was stopped",
                })),
            );
        }
    };

    // MCP-881: report per-row failures alongside successes.
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
                    "gcp stop_all: stop_watch failed for one row — continuing"
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
