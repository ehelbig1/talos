use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Extension;
use std::sync::Arc;
use uuid::Uuid;

use talos_secrets_manager::SecretsManager;

// ────────────────────────────────────────────────────────────────────────────
// Suspension callback handler — no auth (correlation_id IS the bearer token)
// ────────────────────────────────────────────────────────────────────────────

/// POST /api/callbacks/:correlation_id
///
/// Called by external systems to resume a workflow suspension.
/// The correlation_id (256-bit random) acts as the bearer token.
/// No authentication middleware — the secrecy of the URL IS the auth.
pub async fn suspension_callback_handler(
    Path(correlation_id): axum::extract::Path<String>,
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(registry): Extension<Arc<talos_registry::ModuleRegistry>>,
    Extension(nats_client): Extension<Option<Arc<async_nats::Client>>>,
    Extension(secrets_manager): Extension<Option<Arc<SecretsManager>>>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    // Validate: exactly 64 lowercase hex chars
    if correlation_id.len() != 64 || !correlation_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "Not found"
            })),
        )
            .into_response();
    }

    // Parse body as JSON payload (treat parse errors as empty payload, not 400)
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::json!({}));

    // Atomic check-and-claim: a single UPDATE...WHERE status='waiting'...RETURNING
    // closes the TOCTOU window between SELECT (status='waiting') and UPDATE
    // (mark resumed). Without this, two concurrent POSTs to the same
    // correlation_id both pass a separate SELECT and both fire the
    // continuation workflow before either UPDATE lands. With the atomic
    // claim, exactly one wins; the loser gets None and returns 404.
    let row = sqlx::query(
        "UPDATE workflow_suspensions \
         SET status='resumed', resumed_at=now(), resumed_by='callback_url', resumed_payload=$1 \
         WHERE correlation_id = $2 AND status = 'waiting' \
         RETURNING id, user_id, continuation_workflow_id",
    )
    .bind(&payload)
    .bind(&correlation_id)
    .fetch_optional(&db_pool)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": "Suspension not found or already consumed"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("suspension_callback_handler DB claim failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "Internal error"
                })),
            )
                .into_response();
        }
    };

    use sqlx::Row;
    let suspension_id: Uuid = row.get("id");
    let user_id: Uuid = row.get("user_id");
    let continuation_id: Option<Uuid> = row.get("continuation_workflow_id");

    // Trigger continuation workflow if configured
    let exec_id = if let Some(wf_id) = continuation_id {
        let Some(sm) = secrets_manager.clone() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "SecretsManager extension missing"})),
            )
                .into_response();
        };
        talos_continuation_trigger::trigger_continuation_workflow(
            &db_pool,
            registry,
            nats_client,
            sm,
            user_id,
            wf_id,
            &payload,
            suspension_id,
            talos_continuation_trigger::TriggerSourceKind::WorkflowSuspension,
        )
        .await
    } else {
        None
    };

    // Note: the suspension was already marked resumed by the atomic
    // claim UPDATE above. No second UPDATE is needed.

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "resumed": true,
            "execution_id": exec_id,
        })),
    )
        .into_response()
}
