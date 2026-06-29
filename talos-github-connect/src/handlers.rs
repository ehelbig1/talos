//! Axum handlers for the GitHub App connect flow (RFC 0008 B2b).
//!
//! Route wiring (in `controller/src/main.rs`, B2b-3):
//! * `GET /api/github/connect` — session-authenticated (`rest_auth_middleware`
//!   injects `Extension<Uuid>`); returns the install-redirect URL as JSON.
//! * `GET /api/github/setup` — the App's "Setup URL" callback; NOT auth-gated
//!   (cross-site redirect from github.com carries no `SameSite=Strict` cookie);
//!   `user_id` is recovered from the state token.
//!
//! Both live under `/api/`, which the chart's nginx ConfigMap already proxies —
//! no new `location` block needed.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::service::GithubConnectService;

/// `GET /api/github/connect` — start the install flow.
pub async fn connect_github_handler(
    State(svc): State<Arc<GithubConnectService>>,
    axum::Extension(user_id): axum::Extension<Uuid>,
) -> impl IntoResponse {
    if !svc.is_configured() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "GitHub App is not configured on this server",
            })),
        )
            .into_response();
    }

    match svc.begin_install(user_id).await {
        Ok(install_url) => Json(serde_json::json!({
            "success": true,
            "install_url": install_url,
        }))
        .into_response(),
        Err(e) => {
            // Log server-side; return a generic message (no internal detail).
            tracing::error!(user_id = %user_id, error = %e, "GitHub App connect: begin_install failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Failed to initiate GitHub App install",
                })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SetupParams {
    pub installation_id: Option<String>,
    pub setup_action: Option<String>,
    pub state: Option<String>,
}

/// `GET /api/github/setup` — the GitHub App Setup-URL callback.
pub async fn github_setup_callback_handler(
    Query(params): Query<SetupParams>,
    State(svc): State<Arc<GithubConnectService>>,
) -> impl IntoResponse {
    let frontend_url = talos_config::get_frontend_url();
    let err_redirect = |code: &str| {
        Redirect::to(&format!(
            "{}/settings?github_error={}#integrations",
            frontend_url,
            urlencoding::encode(code)
        ))
    };

    let state = match params.state.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            tracing::warn!("GitHub App setup callback missing state");
            return err_redirect("missing_state").into_response();
        }
    };

    match svc
        .handle_setup(
            params.installation_id.as_deref(),
            params.setup_action.as_deref(),
            &state,
        )
        .await
    {
        Ok(outcome) => {
            tracing::info!(account = %outcome.account_login, "GitHub App installed");
            Redirect::to(&format!(
                "{}/settings?github_connected={}#integrations",
                frontend_url,
                urlencoding::encode(&outcome.account_login)
            ))
            .into_response()
        }
        Err(e) => {
            // Generic code to the browser; full error server-side only.
            tracing::warn!(error = %e, "GitHub App setup callback failed");
            err_redirect("install_failed").into_response()
        }
    }
}
