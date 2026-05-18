use super::{GmailIntegrationInfo, GmailIntegrationService};
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<Vec<GmailIntegrationInfo>> {
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<GmailIntegrationInfo> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
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

/// Initiate Gmail OAuth flow
pub async fn connect_gmail_handler(
    State(service): State<Arc<GmailIntegrationService>>,
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

/// Handle Gmail OAuth callback
pub async fn gmail_callback_handler(
    Query(params): Query<OAuthCallbackParams>,
    State(service): State<Arc<GmailIntegrationService>>,
    Extension(user_id): Extension<Uuid>,
) -> impl IntoResponse {
    // Check for OAuth errors
    if let Some(error) = params.error {
        tracing::warn!("Gmail OAuth error: {}", error);
        // Redirect to frontend with error
        return Redirect::to(&format!(
            "/settings?gmail_error={}",
            urlencoding::encode(&error)
        ))
        .into_response();
    }

    // Get authorization code
    let code = match params.code {
        Some(c) => c,
        None => {
            tracing::warn!("Missing authorization code in Gmail OAuth callback");
            return Redirect::to("/settings?gmail_error=missing_code").into_response();
        }
    };

    let _state = match params.state {
        Some(s) => s,
        None => {
            tracing::warn!("Missing state parameter in Gmail OAuth callback");
            return Redirect::to("/settings?gmail_error=missing_state").into_response();
        }
    };

    // Exchange code for tokens and create integration
    match service.handle_callback(user_id, code).await {
        Ok(integration) => {
            tracing::info!(
                "Successfully connected Gmail account: {}",
                integration.email_address
            );
            Redirect::to(&format!(
                "/settings?gmail_connected={}",
                urlencoding::encode(&integration.email_address)
            ))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("Failed to complete Gmail OAuth: {}", e);
            Redirect::to(&format!(
                "/settings?gmail_error={}",
                urlencoding::encode(&e.to_string())
            ))
            .into_response()
        }
    }
}
