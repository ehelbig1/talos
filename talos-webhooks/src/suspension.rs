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

/// Maximum accepted callback body. The persisted `resumed_payload` is a JSONB
/// column read back by operators and handed to the continuation workflow as
/// trigger input; 64 KiB is generous for a resume signal and is the same cap
/// `webhook_request_log` applies to inbound bodies. The route layer in
/// `controller/src/bootstrap/router.rs` uses this SAME constant for its
/// `DefaultBodyLimit`, and the handler re-checks it (defence in depth).
pub const SUSPENSION_CALLBACK_MAX_BODY_BYTES: usize = 64 * 1024;

/// POST /api/callbacks/:correlation_id
///
/// Called by external systems to resume a workflow suspension.
/// The correlation_id (256-bit random) acts as the bearer token.
/// No authentication middleware — the secrecy of the URL IS the auth.
///
/// F9 — three things this handler used to get wrong, each fixed here:
/// * A body that did not parse as JSON was silently treated as `{}` and the
///   single-use correlation id was CONSUMED by the atomic claim below — so a
///   malformed POST (a typo, a proxy mangling the body) burned the suspension
///   and the legitimate resume that followed got 404 "already consumed".
///   Unparseable JSON is now a 400 BEFORE the claim; an EMPTY body still means
///   "resume with no payload" (`{}`), since that is a legitimate signal.
/// * No body cap of its own beyond the route's 1 MiB. Now
///   [`SUSPENSION_CALLBACK_MAX_BODY_BYTES`] at both layers.
/// * The payload was persisted to `resumed_payload` unredacted. It is now
///   DLP-redacted for storage; the continuation workflow still receives the
///   original bytes (redaction is a persistence-boundary rule, not a
///   dispatch one).
pub async fn suspension_callback_handler(
    Path(correlation_id): axum::extract::Path<String>,
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(registry): Extension<Arc<talos_registry::ModuleRegistry>>,
    Extension(nats_client): Extension<Option<Arc<async_nats::Client>>>,
    Extension(secrets_manager): Extension<Option<Arc<SecretsManager>>>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if !is_well_formed_correlation_id(&correlation_id) {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "Not found"
            })),
        )
            .into_response();
    }

    // Cap the body BEFORE parsing (the route layer already enforces the same
    // limit; this is the handler's own guarantee).
    if body.len() > SUSPENSION_CALLBACK_MAX_BODY_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            axum::Json(serde_json::json!({
                "error": "Payload too large"
            })),
        )
            .into_response();
    }

    // Parse the body BEFORE the single-use claim. An unparseable body is the
    // caller's error and must not consume the correlation id; an empty body is
    // a bare "resume" and maps to `{}`.
    let payload: serde_json::Value = match parse_callback_body(&body) {
        Ok(v) => v,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "Request body must be valid JSON (or empty)"
                })),
            )
                .into_response();
        }
    };

    // Persist a DLP-redacted copy; dispatch the original (below).
    let stored_payload = talos_dlp_provider::redact_json(&payload);

    // The deployment-wide execution pause (package BG). BEFORE the single-use
    // claim: a resume refused after it would leave the suspension resumed and
    // its continuation never dispatched. This endpoint is unauthenticated —
    // the correlation id IS the capability — so the pause is consulted only
    // when the id names a WAITING suspension with a continuation: an unknown
    // id still gets the 404 below, and a caller cannot learn that the platform
    // is paused without holding a live capability. The peek and the claim can
    // race; the loser of that race is the pause set in between, whose
    // continuation runs — the admitting direction, stated.
    //
    // The lookup is keyed on a non-secret digest (`correlation_id_hash`) and
    // the full id is constant-time compared after fetch, so no query compares
    // the raw capability (the approval-gate pattern, check 41).
    let not_found = || {
        (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "Suspension not found or already consumed"
            })),
        )
            .into_response()
    };
    let peek = sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(
        "SELECT id, correlation_id, continuation_workflow_id FROM workflow_suspensions \
         WHERE correlation_id_hash = $1 AND status = 'waiting'",
    )
    .bind(talos_text_util::sha256_hex(&correlation_id))
    .fetch_optional(&db_pool)
    .await;
    let (suspension_row_id, continuation_waiting) = match peek {
        Ok(Some((id, stored, continuation)))
            if correlation_id_matches(&stored, &correlation_id) =>
        {
            (id, continuation)
        }
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!("suspension_callback_handler: suspension peek failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response();
        }
    };
    if talos_continuation_trigger::resolution_starts_work(true, continuation_waiting) {
        let refused = match talos_execution_pause::gate_start(
            &db_pool,
            talos_execution_pause::PauseGatePath::Continuation,
        )
        .await
        {
            Ok(None) => false,
            Ok(Some(_)) => true,
            Err(e) => {
                tracing::error!(
                    "suspension_callback_handler: execution pause read failed: {}",
                    e
                );
                true
            }
        };
        if refused {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(
                    axum::http::header::RETRY_AFTER,
                    talos_execution_pause::PAUSE_RETRY_AFTER_SECS.to_string(),
                )],
                axum::Json(serde_json::json!({
                    "error": "Workflow execution is paused; the suspension was not resumed and can be resumed again later"
                })),
            )
                .into_response();
        }
    }

    // Atomic check-and-claim on the row the peek matched: a single
    // UPDATE...WHERE status='waiting'...RETURNING, so of two concurrent POSTs
    // exactly one wins and the loser gets None → 404.
    let row = sqlx::query_as::<_, (Uuid, Uuid, Option<Uuid>)>(
        "UPDATE workflow_suspensions \
         SET status='resumed', resumed_at=now(), resumed_by='callback_url', resumed_payload=$1 \
         WHERE id = $2 AND status = 'waiting' \
         RETURNING id, user_id, continuation_workflow_id",
    )
    .bind(&stored_payload)
    .bind(suspension_row_id)
    .fetch_optional(&db_pool)
    .await;

    let (suspension_id, user_id, continuation_id) = match row {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
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

/// Exactly 64 LOWERCASE hex characters — the only form the id is minted in
/// (`hex::encode` of 32 random bytes). Anything else cannot match a row.
fn is_well_formed_correlation_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Constant-time comparison of the stored and presented correlation ids.
fn correlation_id_matches(stored: &str, provided: &str) -> bool {
    use subtle::ConstantTimeEq;
    !stored.is_empty() && stored.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() == 1
}

/// Parse a callback body: empty (or whitespace-only) → `{}`; otherwise it must
/// be valid JSON. Pure so the "does not consume the claim" contract can be
/// pinned without a database.
fn parse_callback_body(body: &[u8]) -> Result<serde_json::Value, ()> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_slice(body).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_is_a_bare_resume() {
        assert_eq!(parse_callback_body(b"").unwrap(), serde_json::json!({}));
        assert_eq!(parse_callback_body(b"  \n").unwrap(), serde_json::json!({}));
    }

    #[test]
    fn malformed_json_is_rejected_rather_than_coerced_to_empty() {
        // Pre-fix `unwrap_or(json!({}))` made this `{}` and the claim ran.
        assert!(parse_callback_body(b"{not json").is_err());
        assert!(parse_callback_body(b"resume=1").is_err());
    }

    #[test]
    fn valid_json_passes_through_verbatim() {
        let v = parse_callback_body(br#"{"approved":true,"note":"ok"}"#).unwrap();
        assert_eq!(v["approved"], true);
        assert_eq!(v["note"], "ok");
    }

    #[test]
    fn body_cap_matches_the_request_log_ceiling() {
        assert_eq!(SUSPENSION_CALLBACK_MAX_BODY_BYTES, 65_536);
    }

    #[test]
    fn only_lowercase_hex_ids_are_well_formed() {
        let ok = "a".repeat(64);
        assert!(is_well_formed_correlation_id(&ok));
        assert!(is_well_formed_correlation_id(&"0123456789abcdef".repeat(4)));
        assert!(!is_well_formed_correlation_id(&"A".repeat(64)));
        assert!(!is_well_formed_correlation_id(&"a".repeat(63)));
        assert!(!is_well_formed_correlation_id(&"g".repeat(64)));
    }

    #[test]
    fn correlation_ids_compare_exactly() {
        let id = "0123456789abcdef".repeat(4);
        assert!(correlation_id_matches(&id, &id));
        assert!(!correlation_id_matches(&id, &"0".repeat(64)));
        assert!(!correlation_id_matches("", ""));
    }
}
