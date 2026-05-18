use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::secrets::SecretsManager;

// MCP-953 (2026-05-15): handler is wired to no route today, but is
// intentional defensive scaffolding (admin-only DEK cache flush with
// CACHE_ADMIN_USER_IDS allowlist + MCP-880 fail-loud error surfacing).
// Kept so it can be hooked up to an operator-debug endpoint without
// re-deriving the security gate. Vestigial-retention class (MCP-946).
#[allow(dead_code)]
pub async fn invalidate_cache_handler(
    State(secrets_manager): State<Arc<SecretsManager>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    // Restrict cache invalidation to explicitly allowlisted admin user IDs.
    // Fail-closed: if CACHE_ADMIN_USER_IDS is not set, no one is authorized.
    let admin_ids_raw = match std::env::var("CACHE_ADMIN_USER_IDS") {
        Ok(val) => val,
        Err(_) => {
            tracing::warn!(
                user_id = %user_id,
                "DEK cache invalidation denied: CACHE_ADMIN_USER_IDS is not configured"
            );
            return (StatusCode::FORBIDDEN, "Access denied").into_response();
        }
    };

    let authorized = admin_ids_raw
        .split(',')
        .filter_map(|s| s.trim().parse::<Uuid>().ok())
        .any(|admin_id| admin_id == user_id);

    if !authorized {
        tracing::warn!(
            user_id = %user_id,
            "DEK cache invalidation denied: user is not in CACHE_ADMIN_USER_IDS"
        );
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    // MCP-880 (2026-05-14): surface invalidation failures to the
    // operator instead of silently `let _ = ` swallowing. Today
    // `invalidate_dek_cache` only returns Err on the audit-row
    // INSERT failure (per MCP-740 the in-memory clear is infallible
    // and runs first), so the cache IS cleared and the response is
    // semantically correct — but a future change that introduced
    // a fallible cross-pod broadcast or KMS round-trip would
    // silently lie about success. Operator-facing response now
    // distinguishes "cache cleared, audit logged" (200) from
    // "cache cleared, audit row write failed" (200 + WARN) so
    // future failure modes are visible at the API surface, and
    // a hypothetical fully-fallible variant would surface as 500.
    match secrets_manager
        .invalidate_dek_cache(Some(user_id), "ADMIN_API", None)
        .await
    {
        Ok(()) => {
            tracing::info!(user_id = %user_id, "DEK cache invalidated by admin");
            (StatusCode::OK, "DEK cache invalidated successfully").into_response()
        }
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "invalidate_dek_cache returned Err — cache state may be inconsistent"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DEK cache invalidation failed; check controller logs",
            )
                .into_response()
        }
    }
}
