//! The two HTTP handlers of the connect flow.
//!
//! `connect` is behind session auth and sets the browser-binding cookie;
//! `callback` carries no session (the session cookie is `SameSite=Strict` and
//! does not arrive on Google's redirect) and is authenticated by the state
//! token plus that binding. Listing and disconnecting are the generic
//! `serviceIntegrations` / `disconnectServiceIntegration` paths, driven by the
//! provider registry.

use super::{ConnectRefusal, GoogleHealthService};
use axum::{
    extract::{Query, State},
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
    pub csrf_token: String,
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

fn refused(status: StatusCode, message: &str) -> axum::response::Response {
    (
        status,
        Json(ApiResponse::<OAuthUrlResponse> {
            success: false,
            data: None,
            error: Some(message.to_string()),
        }),
    )
        .into_response()
}

/// Start the connect: returns the authorize URL and sets the binding cookie.
pub async fn connect_handler(
    State(service): State<Arc<GoogleHealthService>>,
    Extension(user_id): Extension<Uuid>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !service.is_configured() {
        return refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "Google OAuth is not configured on this server",
        );
    }
    // The state is bound to THIS browser: a URL minted here cannot be
    // completed in someone else's (talos_oauth::connect_binding).
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
            tracing::error!("Failed to generate Google Health auth URL: {e}");
            refused(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to initiate OAuth flow",
            )
        }
    }
}

/// The code a failed callback shows the settings page. A closed set: nothing
/// from the request or from an internal error reaches the redirect.
fn failure_code(error: &anyhow::Error) -> &'static str {
    match error.downcast_ref::<ConnectRefusal>() {
        Some(ConnectRefusal::NoHealthScope) => "no_health_scope",
        None => "connect_failed",
    }
}

/// Google's redirect back. Always answers with a redirect to the settings
/// page: `?google_health_connected=1` or `?google_health_error=<code>`.
pub async fn callback_handler(
    Query(params): Query<OAuthCallbackParams>,
    State(service): State<Arc<GoogleHealthService>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let frontend = talos_config::get_frontend_url();
    let back = |query: &str| {
        Redirect::to(&format!("{frontend}/settings?{query}#integrations")).into_response()
    };

    if let Some(error) = params.error {
        // Caller-supplied: reduced to the RFC 6749 code shape before it is
        // logged or reflected.
        let safe = talos_config::sanitize_oauth_error_code(&error);
        tracing::warn!("Google Health OAuth error: {safe}");
        return back(&format!(
            "google_health_error={}",
            urlencoding::encode(safe)
        ));
    }
    let (Some(code), Some(state)) = (params.code, params.state) else {
        tracing::warn!("Google Health callback without a code or a state");
        return back("google_health_error=missing_code_or_state");
    };
    match service
        .handle_callback(
            code,
            state,
            talos_oauth::presented_connect_binding(&headers).as_deref(),
        )
        .await
    {
        Ok(integration) => {
            tracing::info!(integration_id = %integration.id, "Google Health connect completed");
            back("google_health_connected=1")
        }
        Err(e) => {
            tracing::warn!("Google Health connect failed: {e:#}");
            back(&format!("google_health_error={}", failure_code(&e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_callback_shows_one_of_a_closed_set_of_codes() {
        assert_eq!(
            failure_code(&anyhow::anyhow!(ConnectRefusal::NoHealthScope)),
            "no_health_scope"
        );
        // Whatever an internal error says, the page is shown the generic code.
        assert_eq!(
            failure_code(&anyhow::anyhow!(
                "relation \"google_health_integrations\" does not exist"
            )),
            "connect_failed"
        );
    }
}
