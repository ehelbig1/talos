use super::api::GcpApiClient;
use super::integration::{GoogleCloudIntegrationInfo, GoogleCloudIntegrationService};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Redirect},
    Extension,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Response for OAuth initiation.
#[derive(Serialize)]
pub struct OAuthUrlResponse {
    pub authorization_url: String,
    pub csrf_token: String,
}

/// Query params for the OAuth callback.
#[derive(Deserialize)]
pub struct OAuthCallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Generic API response.
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// List the user's Google Cloud integrations.
pub async fn list_integrations_handler(
    State(service): State<Arc<GoogleCloudIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    match service.get_user_integrations(user_id).await {
        Ok(infos) => Json(ApiResponse {
            success: true,
            data: Some(infos),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // Log full error server-side, return generic to client.
            tracing::error!(user_id = %user_id, error = %e, "Failed to list Google Cloud integrations");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<GoogleCloudIntegrationInfo>> {
                    success: false,
                    data: None,
                    error: Some("Failed to list integrations".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Get a specific integration.
pub async fn get_integration_handler(
    Path(integration_id): Path<Uuid>,
    State(service): State<Arc<GoogleCloudIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    match service.get_integration_info(integration_id, user_id).await {
        Ok(Some(info)) => Json(ApiResponse {
            success: true,
            data: Some(info),
            error: None,
        })
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<GoogleCloudIntegrationInfo> {
                success: false,
                data: None,
                error: Some("Integration not found".to_string()),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                integration_id = %integration_id,
                error = %e,
                "Failed to get Google Cloud integration"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<GoogleCloudIntegrationInfo> {
                    success: false,
                    data: None,
                    error: Some("Failed to get integration".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Disconnect a Google Cloud integration.
pub async fn disconnect_integration_handler(
    Path(integration_id): Path<Uuid>,
    State(service): State<Arc<GoogleCloudIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    match service
        .disconnect_integration(integration_id, user_id)
        .await
    {
        Ok(()) => Json(ApiResponse::<()> {
            success: true,
            data: None,
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                integration_id = %integration_id,
                error = %e,
                "Failed to disconnect Google Cloud integration"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("Failed to disconnect integration".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Initiate the Google Cloud OAuth flow. Requires authentication so the
/// user_id can be bound into the state token.
pub async fn connect_gcp_handler(
    State(service): State<Arc<GoogleCloudIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    if !service.is_configured() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<OAuthUrlResponse> {
                success: false,
                data: None,
                error: Some("Google Cloud OAuth is not configured on this server".to_string()),
            }),
        )
            .into_response();
    }

    match service.get_authorization_url(user_id).await {
        Ok((url, csrf_token)) => Json(ApiResponse {
            success: true,
            data: Some(OAuthUrlResponse {
                authorization_url: url,
                csrf_token,
            }),
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::error!(user_id = %user_id, error = %e, "Failed to generate Google Cloud auth URL");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<OAuthUrlResponse> {
                    success: false,
                    data: None,
                    error: Some("Failed to initiate OAuth flow".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Handle the Google Cloud OAuth callback. NO session auth — the user is
/// identified via the state token bound during the connect flow (cross-site
/// redirects from Google may not carry session cookies under SameSite policy).
pub async fn gcp_callback_handler(
    Query(params): Query<OAuthCallbackParams>,
    State(service): State<Arc<GoogleCloudIntegrationService>>,
) -> impl IntoResponse {
    // Canonical FRONTEND_URL validation (rejects ? and # in addition to /).
    let frontend_url = talos_config::get_frontend_url();

    if let Some(error) = params.error {
        tracing::warn!("Google Cloud OAuth error: {}", error);
        let safe_error = talos_config::sanitize_oauth_error_code(&error);
        return Redirect::to(&format!(
            "{}/settings?gcp_error={}#integrations",
            frontend_url,
            urlencoding::encode(safe_error)
        ))
        .into_response();
    }

    let code = match params.code {
        Some(c) => c,
        None => {
            tracing::warn!("Missing authorization code in Google Cloud OAuth callback");
            return Redirect::to(&format!(
                "{}/settings?gcp_error=missing_code#integrations",
                frontend_url
            ))
            .into_response();
        }
    };

    let state = match params.state {
        Some(s) => s,
        None => {
            tracing::warn!("Missing state parameter in Google Cloud OAuth callback");
            return Redirect::to(&format!(
                "{}/settings?gcp_error=missing_state#integrations",
                frontend_url
            ))
            .into_response();
        }
    };

    match service.handle_callback(code, state).await {
        Ok(integration) => {
            let label = integration
                .account_email
                .clone()
                .unwrap_or_else(|| "google-cloud".to_string());
            tracing::info!(
                "Successfully connected Google Cloud account (integration {})",
                integration.id
            );
            Redirect::to(&format!(
                "{}/settings?gcp_connected={}#integrations",
                frontend_url,
                urlencoding::encode(&label)
            ))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("Failed to complete Google Cloud OAuth: {}", e);
            Redirect::to(&format!(
                "{}/settings?gcp_error={}#integrations",
                frontend_url,
                urlencoding::encode("Failed to connect Google Cloud account")
            ))
            .into_response()
        }
    }
}

/// Query params for `GET /api/gcp/projects`.
#[derive(Deserialize)]
pub struct ListProjectsParams {
    pub integration_id: Uuid,
    #[serde(default)]
    pub query: Option<String>,
}

/// GET /api/gcp/projects?integration_id=<uuid>[&query=<crm-query>]
///
/// Session-authed. Resolves the OAuth token internally from the (ownership-
/// gated) integration and returns a single page of Cloud Resource Manager
/// projects.
pub async fn list_projects_handler(
    State(service): State<Arc<GoogleCloudIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
    Query(params): Query<ListProjectsParams>,
) -> impl IntoResponse {
    // Bounded, single page.
    const PAGE_SIZE: u32 = 50;

    // Resolve the (owned) integration → provider_key.
    let integration = match service
        .get_integration(params.integration_id, user_id)
        .await
    {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Integration not found".to_string()),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                integration_id = %params.integration_id,
                error = %e,
                "Failed to resolve Google Cloud integration for projects list"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Failed to list projects".to_string()),
                }),
            )
                .into_response();
        }
    };

    let token = match service
        .get_access_token(user_id, integration.provider_key)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                integration_id = %params.integration_id,
                error = %e,
                "Failed to fetch Google Cloud access token"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Failed to fetch OAuth token".to_string()),
                }),
            )
                .into_response();
        }
    };

    let client = GcpApiClient::new();
    match client
        .search_projects(&token, params.query.as_deref(), PAGE_SIZE, None)
        .await
    {
        Ok(resp) => Json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "projects": resp.projects,
                "next_page_token": resp.next_page_token,
            })),
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                integration_id = %params.integration_id,
                error = %e,
                "Failed to list Google Cloud projects"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Failed to list projects".to_string()),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Watch-channel management endpoints (user-scoped, authenticated)
// ============================================================================

use super::watch::GcpWatchService;
use super::watch_channel_service::{
    list_for_user as list_watches_for_user, push_endpoint_for, GcpWatchSummary,
};

/// GET /api/gcp/watch-channels
pub async fn list_watch_channels_handler(
    State(service): State<Arc<GcpWatchService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    match list_watches_for_user(&service, user_id).await {
        Ok(summaries) => Json(ApiResponse {
            success: true,
            data: Some(summaries),
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::error!(user_id = %user_id, error = %e, "Failed to list GCP watch channels");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<GcpWatchSummary>> {
                    success: false,
                    data: None,
                    error: Some("Failed to list watch channels".to_string()),
                }),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateGcpWatchRequest {
    pub integration_id: Uuid,
    pub expected_sa_email: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub module_id: Option<Uuid>,
}

/// POST /api/gcp/watch-channels
///
/// The response includes `push_endpoint` — the ONLY time the raw push
/// token is returned to the client. The user copies it into their
/// `gcloud pubsub subscriptions create --push-endpoint=...`.
pub async fn create_watch_channel_handler(
    State(service): State<Arc<GcpWatchService>>,
    Extension(user_id): Extension<Uuid>,
    Json(req): Json<CreateGcpWatchRequest>,
) -> impl IntoResponse {
    match service
        .create_watch(
            user_id,
            req.integration_id,
            req.expected_sa_email,
            req.display_name,
            req.module_id,
        )
        .await
    {
        Ok(row) => {
            let base = talos_config::get_frontend_url();
            Json(ApiResponse {
                success: true,
                data: Some(serde_json::json!({
                    "channel_uuid": row.id,
                    "integration_id": row.integration_id,
                    "expected_sa_email": row.expected_sa_email,
                    "display_name": row.display_name,
                    "module_id": row.module_id,
                    // The one place the raw token is surfaced.
                    "push_endpoint": push_endpoint_for(&base, &row.push_token),
                })),
                error: None,
            })
            .into_response()
        }
        Err(e) => {
            // Log full chain server-side, generic to client. create_watch
            // failures carry SA-validation / integration-lookup / sqlx
            // detail — none of which is safe for the API surface.
            tracing::error!(
                user_id = %user_id,
                integration_id = %req.integration_id,
                error = %e,
                "Failed to create GCP watch channel"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Failed to create watch channel".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// POST /api/gcp/watch-channels/{uuid}/test
///
/// Read-only probe: a single `projects:search` (page_size=1) against
/// Google with the connected account's token, plus the stored
/// `last_push_received_ms`. NO side effects — nothing on our side or
/// Google's is mutated (there is no cursor to advance for GCP push).
pub async fn test_watch_channel_handler(
    State(service): State<Arc<GcpWatchService>>,
    Extension(user_id): Extension<Uuid>,
    Path(channel_uuid): Path<Uuid>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    let row = match service.find_by_id(user_id, channel_uuid).await {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Watch not found".into()),
                }),
            )
                .into_response();
        }
    };
    let integration = match service
        .integrations
        .get_integration(row.integration_id, user_id)
        .await
    {
        Ok(Some(i)) => i,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Integration not found".into()),
                }),
            )
                .into_response();
        }
    };
    let token = match service
        .integrations
        .get_access_token(user_id, integration.provider_key)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "Failed to fetch GCP OAuth token for probe"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Failed to fetch OAuth token".to_string()),
                }),
            )
                .into_response();
        }
    };

    let client = GcpApiClient::new();
    match client.search_projects(&token, None, 1, None).await {
        Ok(_) => Json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "oauth_ok": true,
                "duration_ms": start.elapsed().as_millis() as u64,
                "last_push_received_ms": row.last_push_received_ms,
                "note": "read-only probe — no side effects",
            })),
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "GCP OAuth probe failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("GCP probe failed".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// DELETE /api/gcp/watch-channels/{uuid}
pub async fn stop_watch_channel_handler(
    State(service): State<Arc<GcpWatchService>>,
    Extension(user_id): Extension<Uuid>,
    Path(channel_uuid): Path<Uuid>,
) -> impl IntoResponse {
    match service.stop_watch(user_id, channel_uuid).await {
        Ok(_) => Json(ApiResponse {
            success: true,
            data: Some("stopped"),
            error: None,
        }),
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "Failed to stop GCP watch channel"
            );
            Json(ApiResponse {
                success: false,
                data: None::<&str>,
                error: Some("Failed to stop watch channel".to_string()),
            })
        }
    }
}

// ============================================================================
// Pub/Sub push-notification handler
// ============================================================================

use super::dispatch::{
    dispatch_monitoring_incident, parse_monitoring_incident, GcpDispatchContext,
};
use axum::body::Bytes;
use axum::http::HeaderMap;
use talos_integration_helpers::google_jwt::{GoogleOidcVerifier, PubsubPushEnvelope};

pub struct PubsubHandlerState {
    pub verifier: Arc<GoogleOidcVerifier>,
    /// Operator-configured audience (`GCP_PUBSUB_AUDIENCE`, i.e. the
    /// subscription's `--push-auth-token-audience`). Checked against the
    /// JWT `aud` before any DB work.
    pub expected_audience: String,
    pub watch_service: Arc<GcpWatchService>,
    /// Optional dispatch context. When `None`, verified pushes are
    /// recorded (liveness) but no WASM job is published — useful for
    /// bootstrap/dev without a worker pool.
    pub dispatch: Option<GcpDispatchContext>,
}

/// POST /api/gcp/pubsub/{watch_token}
///
/// Receives Cloud Monitoring push notifications via Google Pub/Sub.
/// Ordering is security-critical:
///
///   1. Extract `Authorization: Bearer <jwt>` — 401 if absent.
///   2. Verify the JWT signature + audience + issuer + expiry against
///      Google's JWKs — 401 on failure. NO DB work happens before this.
///   3. Resolve `(user_id, watch row)` from the `{watch_token}` path.
///      No match ⇒ 200 ack (+ warn) — never a 404 (no existence
///      oracle); lookup error ⇒ 200.
///   4. Enforce the PER-WATCH service-account email
///      (`claims.require_service_account(row.expected_sa_email)`) — 401
///      on mismatch (warn logs the channel_uuid only, never the token
///      or email).
///   5. Decode the Pub/Sub envelope + base64 inner payload into the
///      Cloud Monitoring incident. Malformed ⇒ 200 (a sender bug isn't
///      fixed by retrying).
///   6. Record push liveness + dispatch the incident in a background
///      task, and return 200 immediately (Pub/Sub retries non-2xx up to
///      7 days; Redis dedup covers replays).
///
/// Only AUTH failures (steps 1/2/4) return non-2xx. Everything else
/// acks 200 so Pub/Sub doesn't retry a dead message forever.
pub async fn pubsub_push_handler(
    Path(watch_token): Path<String>,
    State(state): State<Arc<PubsubHandlerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // 1. Bearer token.
    let token = match headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => {
            tracing::warn!("gcp pubsub: missing Authorization bearer");
            return StatusCode::UNAUTHORIZED;
        }
    };

    // 2. Verify signature + audience + issuer + expiry. NO DB before this.
    let claims = match state
        .verifier
        .verify_signed(token, &state.expected_audience)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "gcp pubsub: JWT verification failed");
            return StatusCode::UNAUTHORIZED;
        }
    };

    // 3. Resolve the owning user + watch row from the URL token.
    let (user_id, row) = match state.watch_service.find_by_push_token(&watch_token).await {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            // No active watch for this token (revoked / stale). Ack — do
            // NOT 404 (that would leak whether a token is valid).
            tracing::warn!("gcp pubsub: no active watch for token; acking");
            return StatusCode::OK;
        }
        Err(e) => {
            tracing::error!(error = %e, "gcp pubsub: watch lookup failed; acking");
            return StatusCode::OK;
        }
    };

    // 4. Enforce the PER-WATCH service account. Log channel_uuid only —
    //    never the token or the email (PII / secret).
    if let Err(e) = claims.require_service_account(&row.expected_sa_email) {
        tracing::warn!(
            channel_uuid = %row.id,
            error = %e,
            "gcp pubsub: service-account mismatch"
        );
        // Surface to the owner's UI via recent_failure enrichment.
        audit_push_rejected(&state.watch_service.pool, user_id, &row, &e.to_string()).await;
        return StatusCode::UNAUTHORIZED;
    }

    // 5. Decode envelope → base64 inner payload → Cloud Monitoring JSON.
    let env: PubsubPushEnvelope = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "gcp pubsub: malformed envelope");
            return StatusCode::OK;
        }
    };
    let payload = match decode_pubsub_payload(&env.message.data) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "gcp pubsub: malformed payload");
            return StatusCode::OK;
        }
    };
    let parsed = parse_monitoring_incident(&payload);
    let pubsub_message_id = env.message.message_id.clone();

    // 6. Record liveness + dispatch off the hot path; ack immediately.
    let svc = Arc::clone(&state.watch_service);
    let dispatch_ctx = state.dispatch.clone();
    let channel_uuid = row.id;
    tokio::spawn(async move {
        if let Err(e) = svc.record_push_received(user_id, channel_uuid).await {
            tracing::warn!(error = %e, "gcp pubsub: record_push_received failed");
        }
        if let Some(ref dispatch_ctx) = dispatch_ctx {
            if let Err(e) = dispatch_monitoring_incident(
                dispatch_ctx,
                user_id,
                &row,
                &parsed.incident,
                &parsed.incident_id,
                &parsed.state,
                &pubsub_message_id,
            )
            .await
            {
                tracing::warn!(%user_id, error = %e, "gcp pubsub: dispatch failed");
            }
        }
    });

    StatusCode::OK
}

/// Decode the base64 (standard) inner Pub/Sub payload into JSON. Errors
/// are opaque — never tell a caller which step failed.
fn decode_pubsub_payload(data: &str) -> Result<serde_json::Value, &'static str> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let bytes = STANDARD
        .decode(data.as_bytes())
        .map_err(|_| "invalid push payload")?;
    serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_| "invalid push payload")
}

/// Best-effort `gcp_channel_push_rejected` audit row (surfaced by the
/// watch summary's `recent_failure`). Error is truncate-then-DLP-
/// scrubbed before persisting.
async fn audit_push_rejected(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    row: &super::watch::GcpWatchRow,
    err: &str,
) {
    let scrubbed = talos_integration_helpers::audit::truncate_and_redact_error(err);
    if let Err(e) = talos_integration_helpers::audit::insert_channel_audit(
        pool,
        talos_integration_helpers::audit::ChannelAuditEvent {
            integration_id: Some(row.integration_id),
            user_id,
            event_type: "gcp_channel_push_rejected",
            target: Some(&row.expected_sa_email),
            success: false,
            error_message: Some(&scrubbed),
            metadata: serde_json::json!({ "channel_uuid": row.id.to_string() }),
        },
    )
    .await
    {
        tracing::warn!(error = %e, "gcp channel_push_rejected audit log insert failed");
    }
}

#[cfg(test)]
mod pubsub_tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use std::collections::HashMap;

    const SA: &str = "talos-gcp-pusher@my-proj.iam.gserviceaccount.com";
    const AUD: &str = "https://talos.example.com/api/gcp/pubsub";

    fn keypair() -> (EncodingKey, DecodingKey, String) {
        let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        let priv_pem = priv_key.to_pkcs1_pem(Default::default()).unwrap();
        let pub_pem = pub_key.to_public_key_pem(Default::default()).unwrap();
        let enc = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
        let dec = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
        (enc, dec, "kid-1".to_string())
    }

    fn sign(enc: &EncodingKey, kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims, enc).unwrap()
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// A verifier that trusts the test keypair, wrapped in state with a
    /// garbage pool (never reached in the reject-before-DB tests).
    fn state_with(
        dec: DecodingKey,
        kid: &str,
        audience: &str,
        dispatch: Option<GcpDispatchContext>,
    ) -> Arc<PubsubHandlerState> {
        let mut map = HashMap::new();
        map.insert(kid.to_string(), dec);
        let verifier = Arc::new(GoogleOidcVerifier::with_keys_for_test(map));
        // Port 1 → immediate connection-refused if the pool is ever
        // touched. For step-1/2 rejections it never is; the short
        // acquire timeout keeps the one test that DOES touch it (the
        // unresolved-token ack) from waiting on the default 30s.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(500))
            .connect_lazy("postgres://127.0.0.1:1/nodb")
            .expect("lazy pool");
        let integrations = Arc::new(
            crate::integration::GoogleCloudIntegrationService::new(pool.clone())
                .expect("integration service"),
        );
        let watch_service = Arc::new(GcpWatchService::new(pool, integrations));
        Arc::new(PubsubHandlerState {
            verifier,
            expected_audience: audience.to_string(),
            watch_service,
            dispatch,
        })
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        h
    }

    fn valid_envelope_body() -> Bytes {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let inner = json!({"version":"1.2","incident":{"incident_id":"i1","state":"open"}});
        let env = json!({
            "message": {
                "data": STANDARD.encode(inner.to_string()),
                "messageId": "m1",
            },
            "subscription": "projects/p/subscriptions/s",
        });
        Bytes::from(serde_json::to_vec(&env).unwrap())
    }

    #[tokio::test]
    async fn missing_bearer_is_unauthorized() {
        let (_, dec, kid) = keypair();
        let state = state_with(dec, &kid, AUD, None);
        let status = pubsub_push_handler(
            Path("sometoken".into()),
            State(state),
            HeaderMap::new(),
            valid_envelope_body(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_audience_is_unauthorized_before_db() {
        // Valid signature but WRONG audience → 401 at step 2, before the
        // (garbage) pool is ever touched.
        let (enc, dec, kid) = keypair();
        let state = state_with(dec, &kid, AUD, None);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": "https://accounts.google.com",
                "email": SA,
                "email_verified": true,
                "aud": "https://WRONG.example/api/gcp/pubsub",
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        let status = pubsub_push_handler(
            Path("sometoken".into()),
            State(state),
            bearer(&token),
            valid_envelope_body(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn sa_email_mismatch_is_unauthorized() {
        // Step 4 gate, tested at the primitive level (reaching it in the
        // full handler needs a persisted watch row → integration test).
        // A valid Google JWT from a DIFFERENT service account must be
        // rejected once matched against the per-watch expected email.
        use talos_integration_helpers::google_jwt::{GoogleOidcClaims, VerifyError};
        let claims = GoogleOidcClaims {
            issuer: "https://accounts.google.com".into(),
            email: "attacker@evil.iam.gserviceaccount.com".into(),
            email_verified: true,
            audience: AUD.into(),
            expires_at: now() + 300,
            issued_at: now(),
        };
        assert!(matches!(
            claims.require_service_account(SA).expect_err("must reject"),
            VerifyError::WrongEmail
        ));
    }

    #[tokio::test]
    async fn valid_jwt_but_unresolved_token_acks_200_no_dispatch() {
        // Valid JWT (correct aud) passes step 2; the garbage watch_token
        // reaches find_by_push_token which errors against the dead pool
        // → step 3 acks 200 (no 404 oracle). dispatch is None → nothing
        // is published.
        let (enc, dec, kid) = keypair();
        let state = state_with(dec, &kid, AUD, None);
        let token = sign(
            &enc,
            &kid,
            json!({
                "iss": "https://accounts.google.com",
                "email": SA,
                "email_verified": true,
                "aud": AUD,
                "iat": now(),
                "exp": now() + 300,
            }),
        );
        let status = pubsub_push_handler(
            Path("a-garbage-but-lookupable-token".into()),
            State(state),
            bearer(&token),
            valid_envelope_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}
