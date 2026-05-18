use super::{AtlassianIntegrationInfo, AtlassianIntegrationService};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Redirect},
    Extension,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize)]
pub struct OAuthUrlResponse {
    pub authorization_url: String,
}

#[derive(Deserialize)]
pub struct OAuthCallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// List user's Atlassian integrations.
pub async fn list_integrations_handler(
    State(service): State<Arc<AtlassianIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    match service.get_user_integrations(user_id).await {
        Ok(integrations) => Json(ApiResponse {
            success: true,
            data: Some(integrations),
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to list Atlassian integrations: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<Vec<AtlassianIntegrationInfo>> {
                    success: false,
                    data: None,
                    error: Some("Failed to list integrations".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Disconnect an Atlassian integration.
pub async fn disconnect_integration_handler(
    Path(integration_id): Path<Uuid>,
    State(service): State<Arc<AtlassianIntegrationService>>,
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
            tracing::error!("Failed to disconnect Atlassian integration: {}", e);
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

/// Initiate Atlassian OAuth flow — returns the authorization URL.
/// Requires authentication so we can store the user_id in the state token.
pub async fn connect_handler(
    State(service): State<Arc<AtlassianIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    if !service.is_configured() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<OAuthUrlResponse> {
                success: false,
                data: None,
                error: Some("Atlassian OAuth is not configured on this server".to_string()),
            }),
        )
            .into_response();
    }

    match service.get_authorization_url(user_id).await {
        Ok((url, _csrf_token)) => Json(ApiResponse {
            success: true,
            data: Some(OAuthUrlResponse {
                authorization_url: url,
            }),
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to generate Atlassian auth URL: {}", e);
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

/// Handle Atlassian OAuth callback — exchanges code for tokens, stores integration.
/// This endpoint does NOT require session auth. The user is identified via the
/// state token stored during the connect flow (cross-site redirects from Atlassian
/// may not carry session cookies due to SameSite policy).
pub async fn callback_handler(
    Query(params): Query<OAuthCallbackParams>,
    State(service): State<Arc<AtlassianIntegrationService>>,
) -> impl IntoResponse {
    // MCP-1021 (2026-05-15): complete the MCP-1000 sweep — route through
    // `talos_config::get_frontend_url()` so all four OAuth-callback
    // handlers (atlassian / gmail / slack / oauth_callback) share ONE
    // validation contract. The pre-fix inline validator here only
    // rejected `/` after the host; the canonical helper ALSO rejects
    // `?` and `#`, so a `FRONTEND_URL=https://attacker.com?to=` shape
    // (which the old inline check missed) now falls back to the
    // localhost default instead of producing
    // `https://attacker.com?to=/settings?...`. Slack and the platform
    // oauth_callback already migrated in MCP-1000/MCP-761; atlassian
    // and gmail were the sweep holdouts.
    let frontend_url = talos_config::get_frontend_url();

    if let Some(error) = params.error {
        tracing::warn!("Atlassian OAuth error: {}", error);
        // MCP-1094: sanitise provider-supplied error.
        let safe_error = talos_config::sanitize_oauth_error_code(&error);
        return Redirect::to(&format!(
            "{}/settings?atlassian_error={}#integrations",
            frontend_url,
            urlencoding::encode(safe_error)
        ))
        .into_response();
    }

    let code = match params.code {
        Some(c) => c,
        None => {
            tracing::warn!("Missing authorization code in Atlassian OAuth callback");
            return Redirect::to(&format!(
                "{}/settings#integrations?atlassian_error=missing_code",
                frontend_url
            ))
            .into_response();
        }
    };

    let state = match params.state {
        Some(s) => s,
        None => {
            tracing::warn!("Missing state parameter in Atlassian OAuth callback");
            return Redirect::to(&format!(
                "{}/settings#integrations?atlassian_error=missing_state",
                frontend_url
            ))
            .into_response();
        }
    };

    match service.handle_callback(code, state).await {
        Ok(integration) => {
            let name = integration
                .display_name
                .as_deref()
                .unwrap_or(&integration.site_url);
            tracing::info!("Successfully connected Atlassian site: {}", name);
            Redirect::to(&format!(
                "{}/settings?atlassian_connected={}#integrations",
                frontend_url,
                urlencoding::encode(name)
            ))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("Failed to complete Atlassian OAuth: {}", e);
            Redirect::to(&format!(
                "{}/settings?atlassian_error={}#integrations",
                frontend_url,
                urlencoding::encode("Failed to connect Atlassian account")
            ))
            .into_response()
        }
    }
}
