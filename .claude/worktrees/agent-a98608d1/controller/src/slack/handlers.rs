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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<Vec<SlackIntegrationInfo>> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<SlackIntegrationInfo> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

/// Initiate Slack OAuth flow
pub async fn connect_slack_handler(
    State(service): State<Arc<SlackIntegrationService>>,
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

    match service.get_authorization_url().await {
        Ok((url, csrf_token)) => Json(ApiResponse {
            success: true,
            data: Some(OAuthUrlResponse {
                authorization_url: url,
                csrf_token,
            }),
            error: None,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<OAuthUrlResponse> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

/// Handle Slack OAuth callback
pub async fn slack_callback_handler(
    Query(params): Query<OAuthCallbackParams>,
    State(service): State<Arc<SlackIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    // Check for OAuth errors
    if let Some(error) = params.error {
        tracing::warn!("Slack OAuth error: {}", error);
        // Redirect to frontend with error
        return Redirect::to(&format!(
            "/settings?slack_error={}",
            urlencoding::encode(&error)
        ))
        .into_response();
    }

    // Get authorization code
    let code = match params.code {
        Some(c) => c,
        None => {
            tracing::warn!("Missing authorization code in Slack OAuth callback");
            return Redirect::to("/settings?slack_error=missing_code").into_response();
        }
    };

    let state = match params.state {
        Some(s) => s,
        None => {
            tracing::warn!("Missing state parameter in Slack OAuth callback");
            return Redirect::to("/settings?slack_error=missing_state").into_response();
        }
    };

    // Exchange code for tokens and create integration
    match service.handle_callback(user_id, code, state).await {
        Ok(integration) => {
            tracing::info!(
                "Successfully connected Slack workspace: {} (team_id: {})",
                integration.team_name,
                integration.team_id
            );
            Redirect::to(&format!(
                "/settings?slack_connected={}",
                integration.team_name
            ))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("Failed to complete Slack OAuth: {}", e);
            Redirect::to(&format!(
                "/settings?slack_error={}",
                urlencoding::encode(&e.to_string())
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

#[derive(Debug, Serialize)]
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

pub async fn create_app_handler(
    State(client): State<Arc<crate::slack::SlackApiClient>>,
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
        "Creating Slack app with manifest: {}",
        serde_json::to_string_pretty(&manifest).unwrap_or_default()
    );

    // Create app via Slack API
    match client
        .create_app_from_manifest(&req.user_token, manifest)
        .await
    {
        Ok(response) => {
            tracing::info!("Slack app created successfully: {:?}", response);

            let app_data = response.get("app").and_then(|a| a.as_object());
            let credentials = response.get("credentials").and_then(|c| c.as_object());

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
                    error: Some(e.to_string()),
                }),
            )
                .into_response()
        }
    }
}
