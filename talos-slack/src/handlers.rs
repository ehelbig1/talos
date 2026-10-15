use super::{SlackIntegrationInfo, SlackIntegrationService};
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
    headers: axum::http::HeaderMap,
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

    // Bind the state to THIS browser (connect-binding cookie): the callback
    // must present it, so a URL minted here cannot be completed by someone
    // else's browser — see talos_oauth::connect_binding.
    let binding = talos_oauth::BrowserBinding::for_request(&headers);
    match service.get_authorization_url(user_id, &binding).await {
        Ok((url, csrf_token)) => (
            [binding.set_cookie_pair()],
            Json(ApiResponse {
                success: true,
                data: Some(OAuthUrlResponse {
                    authorization_url: url,
                    csrf_token,
                }),
                error: None,
            }),
        )
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
    headers: axum::http::HeaderMap,
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
        // MCP-1094: sanitise the caller-supplied error to RFC 6749 enum shape
        // BEFORE it is logged (raw, it is attacker-chosen log content) or
        // reflected into the dashboard redirect URL.
        let safe_error = talos_config::sanitize_oauth_error_code(&error);
        tracing::warn!("Slack OAuth error: {}", safe_error);
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
    match service
        .handle_callback(
            code,
            state,
            // The connect-binding cookie set at /connect — the consume refuses a
            // state started in a different browser.
            talos_oauth::presented_connect_binding(&headers).as_deref(),
        )
        .await
    {
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

/// What creating a Slack app answers. The app's three credentials are
/// STORED in the vault under the caller and named here by path; their values
/// never leave the controller (security review 2026-10-14, F-9 — until then
/// the response carried them, into browser devtools and any response-logging
/// proxy).
#[derive(Serialize, Debug)]
pub struct CreateAppResponse {
    pub success: bool,
    pub app_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_path: Option<String>,
    pub signing_secret_path: Option<String>,
    pub verification_token_path: Option<String>,
    pub bot_user_id: Option<String>,
    pub error: Option<String>,
}

impl CreateAppResponse {
    fn failed(error: &str, app_id: Option<String>) -> Self {
        Self {
            success: false,
            app_id,
            client_id: None,
            client_secret_path: None,
            signing_secret_path: None,
            verification_token_path: None,
            bot_user_id: None,
            error: Some(error.to_string()),
        }
    }
}

/// The vault path a created app's credential is stored at, or `None` when the
/// app id Slack returned is not a plain identifier (it names a path).
#[must_use]
pub fn slack_app_secret_path(app_id: &str, credential: &str) -> Option<String> {
    let plain = !app_id.is_empty()
        && app_id.len() <= 32
        && app_id.chars().all(|c| c.is_ascii_alphanumeric());
    plain.then(|| format!("slack/app/{}/{credential}", app_id.to_ascii_lowercase()))
}

pub async fn create_app_handler(
    State(client): State<Arc<crate::SlackApiClient>>,
    Extension(user_id): Extension<Uuid>,
    Extension(secrets): Extension<Arc<talos_secrets_manager::SecretsManager>>,
    ApiJson(req): ApiJson<CreateAppRequest>,
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

    let response = match client
        .create_app_from_manifest(&req.user_token, manifest)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            // MCP-923: server-side log already present; tighten client message to generic.
            tracing::error!("Failed to create Slack app: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CreateAppResponse::failed(
                    "Failed to create Slack app",
                    None,
                )),
            )
                .into_response();
        }
    };
    // SECURITY: Do NOT log the full response — Slack's apps.manifest.create
    // returns client_secret, signing_secret and verification_token in
    // `credentials.*`.
    let app_data = response.get("app").and_then(|a| a.as_object());
    let credentials = response.get("credentials").and_then(|c| c.as_object());
    let field = |obj: Option<&serde_json::Map<String, serde_json::Value>>, key: &str| {
        obj.and_then(|o| o.get(key))
            .and_then(|v| v.as_str())
            .map(String::from)
    };
    let app_id = field(app_data, "id");
    tracing::info!(app_id = ?app_id, "Slack app created successfully");

    // Store each credential under the caller; answer with its path.
    let mut paths: [Option<String>; 3] = [None, None, None];
    for (i, credential) in ["client_secret", "signing_secret", "verification_token"]
        .into_iter()
        .enumerate()
    {
        let Some(value) = field(credentials, credential) else {
            continue;
        };
        let Some(path) = app_id
            .as_deref()
            .and_then(|id| slack_app_secret_path(id, credential))
        else {
            tracing::error!("Slack returned an app id that cannot name a vault path");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CreateAppResponse::failed(
                    "The Slack app was created but its credentials could not be stored; \
                     regenerate them in Slack",
                    app_id,
                )),
            )
                .into_response();
        };
        if let Err(e) = secrets
            .upsert_secret(
                &format!("Slack app {credential}"),
                &path,
                &value,
                "default",
                Some("written when the Slack app was created"),
                user_id,
                Vec::new(),
                None,
            )
            .await
        {
            tracing::error!(error = %e, %user_id, "storing a Slack app credential failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CreateAppResponse::failed(
                    "The Slack app was created but its credentials could not be stored; \
                     regenerate them in Slack",
                    app_id,
                )),
            )
                .into_response();
        }
        paths[i] = Some(path);
    }
    let [client_secret_path, signing_secret_path, verification_token_path] = paths;
    Json(CreateAppResponse {
        success: true,
        client_id: field(credentials, "client_id"),
        bot_user_id: field(app_data, "bot_user_id"),
        app_id,
        client_secret_path,
        signing_secret_path,
        verification_token_path,
        error: None,
    })
    .into_response()
}

#[cfg(test)]
mod create_app_tests {
    use super::*;

    /// F-9 (2026-10-14): a created app's credentials are named by vault path,
    /// and the response has no field that could carry their values.
    #[test]
    fn the_response_names_paths_and_carries_no_credential() {
        assert_eq!(
            slack_app_secret_path("A0123BC", "client_secret").as_deref(),
            Some("slack/app/a0123bc/client_secret")
        );
        for bad in ["", "A/../B", "A B", &"A".repeat(33)] {
            assert_eq!(slack_app_secret_path(bad, "client_secret"), None, "{bad}");
        }
        let body = serde_json::to_value(CreateAppResponse::failed("x", None)).unwrap();
        for leaked in ["client_secret", "signing_secret", "verification_token"] {
            assert!(body.get(leaked).is_none(), "{leaked} is a response field");
        }
    }
}
