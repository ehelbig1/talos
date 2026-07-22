use super::{GmailIntegrationInfo, GmailIntegrationService};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Redirect},
    Extension,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use talos_integration_helpers::api_json::ApiJson;
use uuid::Uuid;

/// Response for OAuth initiation
#[derive(Serialize)]
pub struct OAuthUrlResponse {
    pub authorization_url: String,
    pub csrf_token: String,
}

/// Query params for OAuth callback
#[derive(Deserialize)]
pub struct OAuthCallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Generic API response
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// List user's Gmail integrations
pub async fn list_integrations_handler(
    State(service): State<Arc<GmailIntegrationService>>,
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
            // MCP-924 (2026-05-14): log full error server-side, return
            // generic message to client. Same class as MCP-923 (the
            // talos-slack sweep); this file's `disconnect_integration_
            // handler` and `renew_watch_channel_handler` were already
            // fixed via MCP-581 / MCP-764, but six other branches in
            // the same file still leaked `anyhow::Error::to_string()`
            // (sqlx schema, vault paths, upstream Google API JSON,
            // token-detail). Mirror talos-atlassian's canonical
            // pattern across all eight sites.
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "Failed to list Gmail integrations"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<GmailIntegrationInfo>> {
                    success: false,
                    data: None,
                    error: Some("Failed to list integrations".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Get a specific integration
pub async fn get_integration_handler(
    Path(integration_id): Path<Uuid>,
    State(service): State<Arc<GmailIntegrationService>>,
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
            Json(ApiResponse::<GmailIntegrationInfo> {
                success: false,
                data: None,
                error: Some("Integration not found".to_string()),
            }),
        )
            .into_response(),
        Err(e) => {
            // MCP-924: log server-side, generic to client. See list_integrations_handler.
            tracing::error!(
                user_id = %user_id,
                integration_id = %integration_id,
                error = %e,
                "Failed to get Gmail integration"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<GmailIntegrationInfo> {
                    success: false,
                    data: None,
                    error: Some("Failed to get integration".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Disconnect a Gmail integration
pub async fn disconnect_integration_handler(
    Path(integration_id): Path<Uuid>,
    State(service): State<Arc<GmailIntegrationService>>,
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
            // MCP-581: log full + return generic. Mirror talos-atlassian
            // and (post-MCP-581) talos-google-calendar. The inner
            // anyhow chain can include vault paths, sqlx schema
            // fragments, and upstream Google API response bodies.
            tracing::error!(
                user_id = %user_id,
                integration_id = %integration_id,
                error = %e,
                "Failed to disconnect Gmail integration"
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

/// Initiate Gmail OAuth flow.
/// Requires authentication so we can store the user_id in the state token.
pub async fn connect_gmail_handler(
    State(service): State<Arc<GmailIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    if !service.is_configured() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<OAuthUrlResponse> {
                success: false,
                data: None,
                error: Some("Gmail OAuth is not configured on this server".to_string()),
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
            // MCP-924: log server-side, generic to client. See list_integrations_handler.
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "Failed to generate Gmail auth URL"
            );
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

/// Handle Gmail OAuth callback — exchanges code for tokens, stores integration.
/// This endpoint does NOT require session auth. The user is identified via the
/// state token stored during the connect flow (cross-site redirects from Google
/// may not carry session cookies due to SameSite policy).
pub async fn gmail_callback_handler(
    Query(params): Query<OAuthCallbackParams>,
    State(service): State<Arc<GmailIntegrationService>>,
) -> impl IntoResponse {
    // MCP-1021 (2026-05-15): route through `talos_config::get_frontend_url()`
    // (same fix as the talos-atlassian sibling handler). The canonical
    // helper rejects `?` and `#` in addition to `/` after the host;
    // the inline validator we removed only rejected `/`. Completes the
    // MCP-1000 sweep — all four OAuth-callback handlers now share one
    // validation contract.
    let frontend_url = talos_config::get_frontend_url();

    // Check for OAuth errors
    if let Some(error) = params.error {
        tracing::warn!("Gmail OAuth error: {}", error);
        // MCP-1094: sanitise provider-supplied error.
        let safe_error = talos_config::sanitize_oauth_error_code(&error);
        return Redirect::to(&format!(
            "{}/settings?gmail_error={}#integrations",
            frontend_url,
            urlencoding::encode(safe_error)
        ))
        .into_response();
    }

    // Get authorization code
    let code = match params.code {
        Some(c) => c,
        None => {
            tracing::warn!("Missing authorization code in Gmail OAuth callback");
            return Redirect::to(&format!(
                "{}/settings?gmail_error=missing_code#integrations",
                frontend_url
            ))
            .into_response();
        }
    };

    let state = match params.state {
        Some(s) => s,
        None => {
            tracing::warn!("Missing state parameter in Gmail OAuth callback");
            return Redirect::to(&format!(
                "{}/settings?gmail_error=missing_state#integrations",
                frontend_url
            ))
            .into_response();
        }
    };

    // Exchange code for tokens and create integration (state validated inside for CSRF protection)
    match service.handle_callback(code, state).await {
        Ok(integration) => {
            tracing::info!(
                "Successfully connected Gmail account: {}",
                integration.email_address
            );
            Redirect::to(&format!(
                "{}/settings?gmail_connected={}#integrations",
                frontend_url,
                urlencoding::encode(&integration.email_address)
            ))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("Failed to complete Gmail OAuth: {}", e);
            Redirect::to(&format!(
                "{}/settings?gmail_error={}#integrations",
                frontend_url,
                urlencoding::encode("Failed to connect Gmail account")
            ))
            .into_response()
        }
    }
}

// ============================================================================
// Watch-channel management endpoints (user-scoped, authenticated)
// ============================================================================

use super::watch::GmailWatchService;
use super::watch_channel_service::{list_for_user as list_watches_for_user, GmailWatchSummary};

/// GET /api/gmail/watch-channels
pub async fn list_watch_channels_handler(
    State(service): State<Arc<GmailWatchService>>,
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
            // MCP-924: log server-side, generic to client. See list_integrations_handler.
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "Failed to list Gmail watch channels"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<GmailWatchSummary>> {
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
pub struct CreateGmailWatchRequest {
    pub integration_id: Uuid,
    #[serde(default)]
    pub label_ids: Option<Vec<String>>,
    #[serde(default)]
    pub module_id: Option<Uuid>,
    /// Optional bound workflow. When set, an inbound push triggers a
    /// full workflow execution instead of a single module job. Takes
    /// precedence over `module_id` when both are supplied.
    #[serde(default)]
    pub workflow_id: Option<Uuid>,
}

/// POST /api/gmail/watch-channels
pub async fn create_watch_channel_handler(
    State(service): State<Arc<GmailWatchService>>,
    Extension(user_id): Extension<Uuid>,
    ApiJson(req): ApiJson<CreateGmailWatchRequest>,
) -> impl IntoResponse {
    match service
        .create_watch(
            user_id,
            req.integration_id,
            req.module_id,
            req.workflow_id,
            req.label_ids,
        )
        .await
    {
        Ok(row) => Json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "channel_uuid": row.id,
                "email_address": row.email_address,
                "topic_name": row.topic_name,
                "history_id": row.history_id,
                "label_ids": row.label_ids,
                "expiration_ms": row.expiration_ms,
                "module_id": row.module_id,
                "workflow_id": row.workflow_id,
            })),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // MCP-924: log server-side, generic to client.
            tracing::error!(
                user_id = %user_id,
                integration_id = %req.integration_id,
                module_id = ?req.module_id,
                workflow_id = ?req.workflow_id,
                error = %e,
                "Failed to create Gmail watch channel"
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

/// POST /api/gmail/watch-channels/:uuid/renew
pub async fn renew_watch_channel_handler(
    State(service): State<Arc<GmailWatchService>>,
    Extension(user_id): Extension<Uuid>,
    Path(channel_uuid): Path<Uuid>,
) -> impl IntoResponse {
    match service.renew_watch(user_id, channel_uuid).await {
        Ok(row) => Json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "channel_uuid": row.id,
                "expiration_ms": row.expiration_ms,
            })),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // MCP-764 (2026-05-13): log full error server-side, return
            // generic message to client. Parity with the MCP-581 pattern
            // applied to `disconnect_integration_handler` in the gcal
            // sibling (and now to gcal's renew handler in the same
            // commit). `service.renew_watch` chains errors from the
            // Gmail API exchange (users.watch / users.stop), the
            // integration-state RPC, and sqlx — any of which can
            // include token-detail, schema fragments, or vault paths.
            // The renew endpoint is user-triggered debugging; operators
            // get the full chain in controller logs, the user sees a
            // generic message safe for browser history / proxy logs.
            // Per CLAUDE.md "NEVER return internal error details to
            // API clients."
            tracing::warn!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "Failed to renew Gmail watch channel"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Failed to renew watch channel".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// POST /api/gmail/watch-channels/:uuid/test
/// Read-only OAuth + reachability probe against Google, like gcal's
/// equivalent. Uses GET users.me/profile since that doesn't
/// advance any cursor — Gmail equivalent of calendarList.list.
pub async fn test_watch_channel_handler(
    State(service): State<Arc<GmailWatchService>>,
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
        .get_integration(user_id, row.integration_id)
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
    let access_token = match service
        .integrations
        .get_access_token(user_id, &integration.email_address)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            // MCP-924: log server-side, generic to client.
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "Failed to fetch Gmail OAuth token for probe"
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

    // GET users.me/profile is the cheapest authenticated Gmail call
    // with zero side effects. We don't reuse the api.rs client for
    // this one-off probe — inline reqwest keeps the client's public
    // surface focused on the watch path.
    // MCP-497: hardened build matches the MCP-471 pattern — never fall
    // back to `Client::new()` which re-enables the default redirect
    // policy. reqwest strips `Authorization` on cross-origin redirects
    // but redirects within the same origin still carry the Bearer
    // token; a same-domain redirect from `gmail.googleapis.com` to a
    // sibling Google endpoint is exactly the kind of legitimate-looking
    // path an attacker would chase if they ever found an open redirect
    // in the Google API surface.
    // MCP-1034: explicit connect_timeout so a slow-loris on the Gmail
    // API endpoint fails fast on TCP-handshake rather than pinning the
    // probe for the full 10s.
    let client = talos_http_utils::trusted_client::build_integration_client(
        std::time::Duration::from_secs(10),
    );
    let resp = client
        .get("https://gmail.googleapis.com/gmail/v1/users/me/profile")
        .bearer_auth(&access_token)
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => Json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "oauth_ok": true,
                "duration_ms": start.elapsed().as_millis() as u64,
                "note": "read-only probe — no cursor advance, no WASM jobs",
            })),
            error: None,
        })
        .into_response(),
        Ok(r) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                error: Some(format!("profile returned {}", r.status())),
            }),
        )
            .into_response(),
        Err(e) => {
            // MCP-924: log server-side, generic to client. reqwest::Error
            // can leak DNS lookup detail, connect-error specifics, and
            // sometimes URL fragments. Probe response wasn't even
            // received — surface a generic "Gmail probe failed" message.
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "Gmail OAuth probe network error"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Gmail probe failed".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// DELETE /api/gmail/watch-channels/:uuid
pub async fn stop_watch_channel_handler(
    State(service): State<Arc<GmailWatchService>>,
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
            // MCP-924: log server-side, generic to client. service.
            // stop_watch chains errors from the Gmail users.stop API,
            // the integration-state RPC, and sqlx — any of which can
            // carry token-detail, vault paths, or schema fragments.
            tracing::error!(
                user_id = %user_id,
                channel_uuid = %channel_uuid,
                error = %e,
                "Failed to stop Gmail watch channel"
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

use super::pubsub_jwt::{decode_gmail_notification, PubsubJwtVerifier, PubsubPushEnvelope};
use axum::body::Bytes;
use axum::http::HeaderMap;

pub struct PubsubHandlerState {
    pub verifier: Arc<PubsubJwtVerifier>,
    pub watch_service: Arc<GmailWatchService>,
    /// Optional dispatch context. When `None`, the push handler
    /// syncs history + advances the cursor but doesn't publish
    /// WASM jobs — useful for bootstrap environments where the
    /// worker pool / NATS isn't wired up yet. When `Some`, every
    /// message added to the mailbox fires a signed `JobRequest`
    /// to the configured module (if one is bound).
    pub dispatch: Option<super::dispatch::GmailDispatchContext>,
}

/// POST /api/gmail/pubsub
///
/// Receives push notifications from Google Pub/Sub. Flow:
///
///   1. Extract `Authorization: Bearer <jwt>` — reject 401 if absent.
///   2. Verify JWT against Google's JWKs + operator-configured
///      audience/email (see `pubsub_jwt.rs`).
///   3. Parse the envelope; base64-decode + JSON-decode the inner
///      `{ emailAddress, historyId }` payload.
///   4. Resolve (user_id, watch_row) via the emailAddress index on
///      gmail_integrations.
///   5. Fetch Gmail history from `row.history_id` forward and advance
///      the stored cursor.
///
/// This commit lands the first four steps — step 5 fetches but does
/// NOT dispatch WASM jobs yet. Dispatch lands in a follow-up so the
/// security envelope can be audited independently from the full
/// workflow pipeline.
///
/// Always returns 200 on "I understood but can't act on this" so
/// Pub/Sub doesn't retry a dead message forever. Returns 401 only
/// when the JWT itself was invalid — that's the only retry-worthy
/// failure, and in practice it indicates a misconfigured
/// subscription rather than a transient issue.
pub async fn pubsub_push_handler(
    State(state): State<Arc<PubsubHandlerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // 1. Extract bearer token from Authorization header.
    let token = match headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => {
            tracing::warn!("gmail pubsub: missing Authorization bearer");
            return StatusCode::UNAUTHORIZED;
        }
    };

    // 2. Verify. This handles signature + claims + audience + issuer
    //    in one shot; see pubsub_jwt.rs for the guarantees.
    if let Err(e) = state.verifier.verify(token).await {
        tracing::warn!(error = %e, "gmail pubsub: JWT verification failed");
        return StatusCode::UNAUTHORIZED;
    }

    // 3. Decode envelope.
    let env: PubsubPushEnvelope = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "gmail pubsub: malformed envelope");
            // 200 — no retry. Pub/Sub malformed-body would mean a
            // sender bug, not something we fix by retrying.
            return StatusCode::OK;
        }
    };
    let notification = match decode_gmail_notification(&env) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "gmail pubsub: malformed payload");
            return StatusCode::OK;
        }
    };

    // 4. Resolve user + watch row.
    let lookup = state
        .watch_service
        .find_by_email(&notification.email_address)
        .await;
    let (user_id, row) = match lookup {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            // User revoked the integration, or a push slipped in
            // after we stopped the watch but before Google deactivated.
            // Nothing to do — ack the message.
            tracing::debug!(
                email = %notification.email_address,
                "gmail pubsub: no active watch; acking"
            );
            return StatusCode::OK;
        }
        Err(e) => {
            tracing::error!(error = %e, "gmail pubsub: lookup failed");
            return StatusCode::OK;
        }
    };

    // 5. Advance the cursor and dispatch. (Stale-comment fix 2026-07-01:
    //    an earlier revision deferred dispatch to a "follow-up commit" —
    //    it landed; `dispatch_history_entries` below is that layer.)
    let svc = Arc::clone(&state.watch_service);
    let dispatch_ctx_opt = state.dispatch.clone();
    // DLP: don't carry the connected account's email (PII) into the WARN-level
    // push logs below — `user_id` (pseudonymous) is already the identifier
    // there. Parity with the MCP-1011 recipient-redaction discipline. (The
    // debug-level "no active watch" log above keeps the email: it has no
    // user_id resolved and is gated off in production.)
    let mut history_id = row.history_id;
    let channel_uuid = row.id;
    // Defensive: skip pagination entirely when the stored cursor is
    // 0. Google rejects startHistoryId=0. We never actually store 0
    // (users.watch always returns a real historyId at create time),
    // but if a migration / bug / race ever left a 0 in the row,
    // better to silently skip than 401-loop every push.
    if history_id == 0 {
        tracing::warn!(%user_id, "gmail push: stored history_id is 0; skipping");
        return StatusCode::OK;
    }
    tokio::spawn(async move {
        let integration = match svc
            .integrations
            .get_integration(user_id, row.integration_id)
            .await
        {
            Ok(Some(i)) => i,
            _ => {
                tracing::warn!(%user_id, "gmail push: integration not found");
                return;
            }
        };
        let token = match svc
            .integrations
            .get_access_token(user_id, &integration.email_address)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "gmail push: access token fetch failed");
                return;
            }
        };
        // Page through history. We deliberately do NOT pass a
        // labelId filter to history.list — the watch itself was
        // created with its label filter, and Google only publishes
        // pushes for matching messages. Re-filtering on history.list
        // would DROP events: history entries record mailbox-level
        // changes that aren't 1:1 with message labels, and for
        // multi-label watches we'd only see events for the first
        // label. Trust the watch's upstream filter; sync everything
        // Google told us about.
        //
        // Each call uses `history_id` as the starting cursor; we
        // advance with the returned next_history_id after each page.
        // If the loop errors midway, the cursor is persisted for
        // pages already processed, so the next push resumes safely.
        // MCP-982: Bound pagination defensively. Google's history.list
        // normally terminates when `nextPageToken` is omitted, but if
        // the API misbehaves or a malformed response carries
        // never-ending pagination, this loop would never exit and the
        // detached tokio task would burn CPU + Google API quota
        // indefinitely. 100 pages × ~100 entries/page comfortably
        // covers the activity rate that fits in a single Pub/Sub push
        // window. If exceeded, log + break; the persisted history_id
        // advances per-page so the next push notification resumes from
        // wherever we stopped — no progress is lost.
        const MAX_HISTORY_PAGES: usize = 100;
        let mut page_token: Option<String> = None;
        let mut pages_processed: usize = 0;
        loop {
            pages_processed += 1;
            if pages_processed > MAX_HISTORY_PAGES {
                tracing::warn!(
                    %user_id,
                    %history_id,
                    pages_processed,
                    "gmail push: hit MAX_HISTORY_PAGES cap; truncating this push. Next push will resume from persisted history_id"
                );
                break;
            }
            let resp = match svc
                .api
                .users_history_list(&token, history_id, None, page_token.as_deref())
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(%user_id, error = %e, "gmail push: history.list failed");
                    return;
                }
            };
            let message_count: usize = resp.history.iter().map(|h| h.messages_added.len()).sum();
            tracing::info!(
                %user_id,
                page_history_id = %resp.next_history_id.unwrap_or(history_id),
                messages_added = message_count,
                "gmail push: history page synced"
            );

            // Dispatch before cursor advance: if dispatch's per-message
            // errors happen, they're logged + captured in execution
            // rows, but don't abort cursor advance (permanent failures
            // shouldn't loop). If the ENTIRE dispatch path errors
            // (e.g. module-load failure), we still advance — Redis
            // dedup ensures the next push doesn't re-dispatch anyway.
            if let Some(ref dispatch_ctx) = dispatch_ctx_opt {
                // Re-read the row each page so module_id changes made
                // while processing land in the next dispatch without
                // waiting for the push loop to finish.
                let current_row = match svc.find_by_id(user_id, channel_uuid).await {
                    Ok(r) => r,
                    Err(_) => row.clone(),
                };
                if let Err(e) = super::dispatch::dispatch_history_entries(
                    dispatch_ctx,
                    user_id,
                    &current_row,
                    &resp.history,
                )
                .await
                {
                    tracing::warn!(%user_id, error = %e, "gmail push: dispatch failed");
                }
            }

            if let Some(h) = resp.next_history_id {
                if h > history_id {
                    history_id = h;
                    if let Err(e) = svc.advance_history_id(user_id, channel_uuid, h).await {
                        tracing::warn!(error = %e, "gmail push: advance_history_id failed");
                    }
                }
            }
            match resp.next_page_token {
                Some(t) => page_token = Some(t),
                None => break,
            }
        }
    });

    StatusCode::OK
}
