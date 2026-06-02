use super::{SlackIntegrationInfo, SlackIntegrationService};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Redirect},
    Extension,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

/// List user's Slack integrations
pub async fn list_integrations_handler(
    State(service): State<Arc<SlackIntegrationService>>,
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
            // MCP-923 (2026-05-14): log full error server-side, return
            // generic message to client. Pre-fix the handler returned
            // `Some(e.to_string())` which leaks the full `anyhow::Error`
            // context chain (sqlx error messages, encryption-layer
            // detail, internal field names) to the API caller — same
            // class as CLAUDE.md's "NEVER return internal error
            // details" rule. Sibling `talos-atlassian::handlers` was
            // already on the canonical pattern (tracing::error + plain
            // string); Slack drifted, Gmail still drifts (MCP-924+
            // sweep next).
            tracing::error!("Failed to list Slack integrations: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<SlackIntegrationInfo>> {
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
    State(service): State<Arc<SlackIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    match service.get_integration(integration_id, user_id).await {
        Ok(Some(info)) => Json(ApiResponse {
            success: true,
            data: Some(info),
            error: None,
        })
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<SlackIntegrationInfo> {
                success: false,
                data: None,
                error: Some("Integration not found".to_string()),
            }),
        )
            .into_response(),
        Err(e) => {
            // MCP-923: log server-side, generic to client. See list_integrations_handler above.
            tracing::error!("Failed to get Slack integration: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<SlackIntegrationInfo> {
                    success: false,
                    data: None,
                    error: Some("Failed to get integration".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Disconnect a Slack integration
pub async fn disconnect_integration_handler(
    Path(integration_id): Path<Uuid>,
    State(service): State<Arc<SlackIntegrationService>>,
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
            // MCP-923: log server-side, generic to client.
            tracing::error!("Failed to disconnect Slack integration: {}", e);
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

/// Initiate Slack OAuth flow
pub async fn connect_slack_handler(
    State(service): State<Arc<SlackIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    if !service.is_configured() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<OAuthUrlResponse> {
                success: false,
                data: None,
                error: Some("Slack OAuth is not configured on this server".to_string()),
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
            // MCP-923: log server-side, generic to client.
            tracing::error!("Failed to generate Slack auth URL: {}", e);
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

/// Handle Slack OAuth callback.
///
/// SECURITY: Identity is recovered from the state token (server-issued
/// at connect time and bound to the originating user_id), NOT from the
/// session cookie. See SlackIntegrationService::handle_callback for
/// rationale. The route is currently still wired up under
/// rest_auth_middleware in main.rs; that's belt-and-braces — a logged-in
/// user in addition to a valid state token. Both must agree on the same
/// user identity (enforced server-side: handle_callback uses ONLY the
/// state token's user_id).
pub async fn slack_callback_handler(
    Query(params): Query<OAuthCallbackParams>,
    State(service): State<Arc<SlackIntegrationService>>,
) -> impl IntoResponse {
    // MCP-761 (2026-05-13): use `talos_config::get_frontend_url()` so
    // split-origin deployments (frontend served from app.example.com,
    // controller from api.example.com) land the user back on the
    // dashboard. Pre-fix the handler used bare relative paths like
    // `/settings?slack_error=...` — relative URLs resolve against the
    // current host (the controller), so the browser redirected to
    // `api.example.com/settings` which doesn't exist on the controller
    // → 404. Sibling handlers `talos-atlassian::callback_handler` and
    // `talos-gmail::gmail_callback_handler` already use frontend_url;
    // Slack was the drift. The helper applies MCP-615 / MCP-653 empty-
    // env filtering and falls back to `http://localhost:3000` in dev.
    let frontend_url = talos_config::get_frontend_url();

    // Check for OAuth errors
    if let Some(error) = params.error {
        tracing::warn!("Slack OAuth error: {}", error);
        // MCP-1094: sanitise provider-supplied error to RFC 6749 enum
        // shape before reflecting into the dashboard redirect URL.
        let safe_error = talos_config::sanitize_oauth_error_code(&error);
        return Redirect::to(&format!(
            "{}/settings?slack_error={}",
            frontend_url,
            urlencoding::encode(safe_error)
        ))
        .into_response();
    }

    // Get authorization code
    let code = match params.code {
        Some(c) => c,
        None => {
            tracing::warn!("Missing authorization code in Slack OAuth callback");
            return Redirect::to(&format!(
                "{}/settings?slack_error=missing_code",
                frontend_url
            ))
            .into_response();
        }
    };

    let state = match params.state {
        Some(s) => s,
        None => {
            tracing::warn!("Missing state parameter in Slack OAuth callback");
            return Redirect::to(&format!(
                "{}/settings?slack_error=missing_state",
                frontend_url
            ))
            .into_response();
        }
    };

    // Exchange code for tokens and create integration. user_id is
    // recovered from the state token inside handle_callback.
    match service.handle_callback(code, state).await {
        Ok(integration) => {
            tracing::info!(
                "Successfully connected Slack workspace: {} (team_id: {})",
                integration.team_name,
                integration.team_id
            );
            // MCP-761: urlencoding::encode the team_name. Pre-fix the
            // raw `integration.team_name` was interpolated directly into
            // the query string — a Slack workspace named "Awesome &
            // Friends" would render as
            // `?slack_connected=Awesome & Friends`, which the browser
            // parses as `slack_connected=Awesome` + a stray
            // `Friends` parameter. A workspace name containing
            // `&attacker_param=value` could inject extra query params
            // visible to the frontend's `/settings` page parser. Sibling
            // handlers in atlassian and gmail already encode. Bounded
            // impact (Slack workspace names are operator-controlled and
            // typically short), but the encode is free and matches the
            // sibling-handler contract.
            Redirect::to(&format!(
                "{}/settings?slack_connected={}",
                frontend_url,
                urlencoding::encode(&integration.team_name)
            ))
            .into_response()
        }
        Err(e) => {
            // MCP-760 (2026-05-13): generic message to caller; full
            // error stays server-side. Pre-fix the handler urlencoded
            // `e.to_string()` into the Redirect URL, leaking
            // `service.handle_callback` internal detail (Slack API
            // response bodies, sqlx errors with table names, OAuth
            // exchange-token response which may carry `client_id` /
            // `client_secret` echo per memory note
            // `secrets_in_logs_via_debug_print` for Slack
            // apps.manifest.create). Redirect URLs persist in browser
            // history, proxy logs, and Referer headers — anything in
            // the query string can leak across security boundaries.
            // Sibling handlers in talos-atlassian (handlers.rs:222) and
            // talos-gmail (handlers.rs:262) already collapse the error
            // to a generic "Failed to connect X account"; this commit
            // brings the Slack handler into parity. The structured
            // error is still logged server-side at WARN for operator
            // diagnosis. Same controller-wide error-hygiene rule as
            // CLAUDE.md "NEVER return internal error details to API
            // clients."
            tracing::warn!("Failed to complete Slack OAuth: {}", e);
            // MCP-761: frontend_url interpolation for split-origin parity.
            Redirect::to(&format!(
                "{}/settings?slack_error={}",
                frontend_url,
                urlencoding::encode("Failed to connect Slack workspace")
            ))
            .into_response()
        }
    }
}

/// Create a new Slack app via Apps Manifest API
#[derive(Debug, Deserialize)]
pub struct CreateAppRequest {
    pub app_name: String,
    pub description: String,
    pub webhook_url: String,
    pub event_types: Vec<String>,
    pub user_token: String, // User OAuth token with apps:write scope
}

#[derive(Serialize)]
pub struct CreateAppResponse {
    pub success: bool,
    pub app_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub signing_secret: Option<String>,
    pub verification_token: Option<String>,
    pub bot_user_id: Option<String>,
    pub error: Option<String>,
}

// Custom Debug so a stray `{:?}` never prints the Slack app secrets. The JSON
// `Serialize` (intentional — the one-time create response returns these to the
// user) is unaffected; only Debug-formatting redacts.
impl std::fmt::Debug for CreateAppResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let red = |o: &Option<String>| o.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("CreateAppResponse")
            .field("success", &self.success)
            .field("app_id", &self.app_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &red(&self.client_secret))
            .field("signing_secret", &red(&self.signing_secret))
            .field("verification_token", &red(&self.verification_token))
            .field("bot_user_id", &self.bot_user_id)
            .field("error", &self.error)
            .finish()
    }
}

pub async fn create_app_handler(
    State(client): State<Arc<crate::SlackApiClient>>,
    Extension(_user_id): Extension<Uuid>,
    Json(req): Json<CreateAppRequest>,
) -> impl IntoResponse {
    // Generate manifest
    let manifest = client.generate_manifest(
        &req.app_name,
        &req.description,
        &req.webhook_url,
        &req.event_types,
    );

    tracing::info!(
        app_name = %req.app_name,
        "Creating Slack app via apps.manifest.create"
    );

    // Create app via Slack API
    match client
        .create_app_from_manifest(&req.user_token, manifest)
        .await
    {
        Ok(response) => {
            // SECURITY: Do NOT log the full response — Slack's
            // apps.manifest.create returns client_secret, signing_secret,
            // and verification_token in `credentials.*`. Logging the raw
            // value (`{:?}`) leaks them into stdout/log aggregators.
            // Log only the non-sensitive app_id.
            let app_data = response.get("app").and_then(|a| a.as_object());
            let credentials = response.get("credentials").and_then(|c| c.as_object());

            let app_id_log = app_data
                .and_then(|a| a.get("id"))
                .and_then(|id| id.as_str())
                .unwrap_or("<unknown>");
            tracing::info!(app_id = %app_id_log, "Slack app created successfully");

            Json(CreateAppResponse {
                success: true,
                app_id: app_data
                    .and_then(|a| a.get("id"))
                    .and_then(|id| id.as_str())
                    .map(String::from),
                client_id: credentials
                    .and_then(|c| c.get("client_id"))
                    .and_then(|id| id.as_str())
                    .map(String::from),
                client_secret: credentials
                    .and_then(|c| c.get("client_secret"))
                    .and_then(|s| s.as_str())
                    .map(String::from),
                signing_secret: credentials
                    .and_then(|c| c.get("signing_secret"))
                    .and_then(|s| s.as_str())
                    .map(String::from),
                verification_token: credentials
                    .and_then(|c| c.get("verification_token"))
                    .and_then(|t| t.as_str())
                    .map(String::from),
                bot_user_id: app_data
                    .and_then(|a| a.get("bot_user_id"))
                    .and_then(|id| id.as_str())
                    .map(String::from),
                error: None,
            })
            .into_response()
        }
        Err(e) => {
            // MCP-923: server-side log already present; tighten client message to generic.
            tracing::error!("Failed to create Slack app: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CreateAppResponse {
                    success: false,
                    app_id: None,
                    client_id: None,
                    client_secret: None,
                    signing_secret: None,
                    verification_token: None,
                    bot_user_id: None,
                    error: Some("Failed to create Slack app".to_string()),
                }),
            )
                .into_response()
        }
    }
}
