//! Shared admin-endpoint plumbing for push integrations.
//!
//! Both `talos-gmail::admin` and `talos-google-calendar::admin` gate
//! their operator endpoints behind the same two-check defense
//! (`ENABLE_ADMIN_OPS` env switch + constant-time `X-Admin-Secret`
//! compare) and audit every successful action to the shared
//! `google_calendar_audit_log`. The skeletons were copy-adapted; this
//! module is the single implementation so integration 3 doesn't
//! re-copy (and so security fixes like MCP-983 / MCP-1064 land once).

use axum::{
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value as JsonValue};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Gate every admin-ops request behind BOTH the big-red-button env
/// var and a constant-time secret compare. Returns `Ok(())` on pass;
/// the pre-built rejection response on fail.
///
/// `integration_label` only feeds the operator warn line (e.g.
/// `"gmail"` / `"gcal"`) — it plays no part in the auth decision.
///
/// # Defense in depth
///
/// 1. `ENABLE_ADMIN_OPS` must be enabled (canonical
///    `talos_config::admin_ops_enabled()` resolver — MCP-1064). In
///    production this MUST be unset; a leaked `ADMIN_SECRET_KEY`
///    alone is not enough to reach these routes.
/// 2. `X-Admin-Secret` header vs `ADMIN_SECRET_KEY`, compared in
///    constant time. Empty `ADMIN_SECRET_KEY` fails closed.
///
/// MCP-983 (2026-05-15): direct `ct_eq` on slices. Pre-fix used a
/// 512-byte padded buffer that silently truncated secrets longer
/// than 512 bytes, letting an attacker who knew the first 512 bytes
/// authenticate against any longer secret. Subtle's slice `ct_eq`
/// returns Choice(0) immediately on length mismatch and runs
/// constant-time over equal-length contents — the implicit length
/// compare leaks a negligible signal under network jitter for
/// sensibly-sized admin secrets.
pub fn authorize_admin_request(
    headers: &HeaderMap,
    integration_label: &str,
) -> Result<(), (StatusCode, Json<JsonValue>)> {
    if !talos_config::admin_ops_enabled() {
        tracing::warn!(
            "admin {integration_label} endpoint hit but ENABLE_ADMIN_OPS is unset/false"
        );
        return Err((StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))));
    }

    let admin_secret = std::env::var("ADMIN_SECRET_KEY").unwrap_or_default();
    let provided = headers
        .get("X-Admin-Secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let bytes_ok = admin_secret.as_bytes().ct_eq(provided.as_bytes());
    if admin_secret.is_empty() || bytes_ok.unwrap_u8() != 1 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        ));
    }
    Ok(())
}

/// Audit-log a successful admin action to the shared
/// `google_calendar_audit_log` (the de-facto cross-integration events
/// log). Insert failure is logged but non-fatal — losing the audit
/// row is a visibility regression, not a correctness one.
///
/// `event_type` is the full column value (callers pre-format their
/// prefix, e.g. `admin_gmail_{action}` / `admin_{action}`); `action`
/// is the structured field on the failure warn; `warn_message` is the
/// integration's historical failure-warn text.
///
/// MCP-1015 (2026-05-15): DLP-redact metadata before persisting —
/// callers pack `e.to_string()` of stop failures into the `failed`
/// array, and those error chains can echo refresh_token /
/// access_token bytes on token-rejection paths. Helper-level scrub
/// covers every current + future caller without per-call discipline.
///
/// MCP-1197 (2026-05-17): measure-first-then-redact via
/// `redact_json_bounded`. Under a wide outage `stop_all` packs one
/// entry per failed integration; with thousands of integrations the
/// `failed` array can exceed 1 MiB and bloat the audit table + WAL.
/// Returning `None` drops the metadata column to NULL (event_type +
/// success still persist, so operators retain the binary signal).
pub async fn log_admin_action(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    event_type: &str,
    action: &str,
    warn_message: &str,
    metadata: JsonValue,
) {
    let scrubbed = talos_dlp_provider::redact_json_bounded(&metadata);
    if let Err(e) = sqlx::query(
        "INSERT INTO google_calendar_audit_log \
         (user_id, event_type, success, metadata) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(event_type)
    .bind(true)
    .bind(scrubbed)
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, action, "{}", warn_message);
    }
}

/// Parse a required UUID field out of an admin request body,
/// returning the historical `400 {"error": "<field> required (uuid)"}`
/// rejection when absent or malformed.
pub fn require_uuid_field(
    body: &JsonValue,
    field: &str,
) -> Result<Uuid, (StatusCode, Json<JsonValue>)> {
    body.get(field)
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("{field} required (uuid)")})),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_uuid_field_accepts_valid_uuid() {
        let id = Uuid::new_v4();
        let body = json!({ "user_id": id.to_string() });
        assert_eq!(require_uuid_field(&body, "user_id").unwrap(), id);
    }

    #[test]
    fn require_uuid_field_rejects_missing_and_malformed() {
        for body in [
            json!({}),
            json!({ "user_id": "not-a-uuid" }),
            json!({ "user_id": 42 }),
            json!({ "user_id": null }),
        ] {
            let (status, Json(payload)) = require_uuid_field(&body, "user_id").unwrap_err();
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                payload.get("error").and_then(|e| e.as_str()),
                Some("user_id required (uuid)")
            );
        }
    }

    #[test]
    fn authorize_fails_closed_without_admin_ops_env() {
        // ENABLE_ADMIN_OPS unset in the test environment → 404 shape,
        // regardless of headers. (Env mutation is deliberately avoided
        // here — process-global env writes race parallel tests.)
        if talos_config::admin_ops_enabled() {
            return; // environment has admin ops enabled; skip
        }
        let headers = HeaderMap::new();
        let (status, _) = authorize_admin_request(&headers, "gmail").unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
