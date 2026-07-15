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
