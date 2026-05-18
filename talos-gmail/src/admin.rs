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
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Gate every request behind BOTH the big-red-button env var and a
/// constant-time secret compare. Returns `Ok(())` on pass; the
/// pre-built rejection response on fail.
fn authorize(headers: &HeaderMap) -> Result<(), (StatusCode, Json<JsonValue>)> {
    // MCP-1064 (2026-05-15): canonical `admin_ops_enabled()` resolver.
    // Pre-fix this site accepted `1 | true` (case-insensitive); the
    // controller secrets-admin sibling accepted ONLY `1`. Same env
    // var, different behaviour across crates. Both now go through the
    // canonical helper which accepts `true | 1 | yes | on`.
    if !talos_config::admin_ops_enabled() {
        tracing::warn!("admin gmail endpoint hit but ENABLE_ADMIN_OPS is unset/false");
        return Err((StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))));
    }

    let admin_secret = std::env::var("ADMIN_SECRET_KEY").unwrap_or_default();
    let provided = headers
        .get("X-Admin-Secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // MCP-983 (2026-05-15): direct ct_eq on slices. Pre-fix used a
    // 512-byte padded buffer with `a[..a.len().min(CT_BUF)].copy_...`
    // — when `admin_secret.len() > 512` the comparison silently
    // truncated to the first 512 bytes, so an attacker who knew the
    // first 512 bytes (plus the true length, via the explicit
    // `a.len() == b.len()` check) could authenticate against any
    // longer secret. Subtle's slice `ct_eq` returns Choice(0)
    // immediately on length mismatch and runs constant-time over
    // equal-length contents — the implicit length compare leaks a
    // negligible signal (microsecond timing on slice length, well
    // under network jitter for sensibly-sized admin secrets). The
    // 512-byte padding was a misguided attempt to mask length;
    // removing it fixes the truncation bug and the length leak it
    // tried to hide isn't exploitable for ≥16-char secrets anyway
    // (search space dominates timing).
    let bytes_ok = admin_secret.as_bytes().ct_eq(provided.as_bytes());
    if admin_secret.is_empty() || bytes_ok.unwrap_u8() != 1 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        ));
    }
    Ok(())
}

async fn log_admin_action(pool: &sqlx::PgPool, user_id: Uuid, action: &str, metadata: JsonValue) {
    // MCP-1015 (2026-05-15): DLP-redact metadata before persisting to
    // the shared google_calendar_audit_log.metadata column. The
    // `stop_all` caller below (line 283) packs `e.to_string()` of
    // `stop_watch` failures into the `failed` array, and those error
    // chains can carry Gmail API error bodies that echo refresh_token
    // / access_token bytes on token-rejection paths. Same persistence-
    // boundary rule as the sibling gcal helper at MCP-1015. Helper-
    // level scrub means every current + future caller is covered
    // without per-call discipline.
    //
    // MCP-1197 (2026-05-17): measure-first-then-redact via
    // `redact_json_bounded`. Under a wide outage `stop_all` packs one
    // entry per failed integration; with thousands of integrations the
    // `failed` array can exceed 1 MiB and bloat the audit table + WAL.
    // Returning `None` drops the metadata column to NULL (the
    // event_type + success fields still persist, so operators retain
    // the binary signal). Sibling of `bound_log_details` in
    // talos-actor-repository (MCP-1195).
    let scrubbed = talos_dlp_provider::redact_json_bounded(&metadata);
    if let Err(e) = sqlx::query(
        "INSERT INTO google_calendar_audit_log \
         (user_id, event_type, success, metadata) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(format!("admin_gmail_{action}"))
    .bind(true)
    .bind(scrubbed)
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, action, "admin gmail audit log insert failed");
    }
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

    let user_id = match body
        .get("user_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "user_id required (uuid)"})),
            )
        }
    };
    let integration_id = match body
        .get("integration_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "integration_id required (uuid)"})),
            )
        }
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

    let user_id = match body
        .get("user_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "user_id required (uuid)"})),
            )
        }
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
