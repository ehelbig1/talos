//! Axum handlers for the GitHub App connect flow (RFC 0008 B2b).
//!
//! Route wiring (in `controller/src/main.rs`, B2b-3):
//! * `GET /api/github/connect` — session-authenticated (`rest_auth_middleware`
//!   injects `Extension<Uuid>`); returns the install-redirect URL as JSON.
//! * `GET /api/github/setup` — the App's "Setup URL" callback; NOT auth-gated
//!   (cross-site redirect from github.com carries no `SameSite=Strict` cookie);
//!   `user_id` is recovered from the state token, and the handler REDIRECTS to
//!   GitHub's user authorization rather than writing anything.
//! * `GET /api/github/authorized` — the App's "Callback URL" (user
//!   authorization); NOT auth-gated for the same reason. Claims the
//!   installation only if the authorizing GitHub user can access it.
//!
//! Every state is bound to the initiating browser: `/connect` sets the
//! `talos_oauth_connect` cookie and both callbacks require it.
//!
//! Both live under `/api/`, which the chart's nginx ConfigMap already proxies —
//! no new `location` block needed.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};
use serde::Deserialize;
use talos_oauth::{presented_connect_binding, BrowserBinding};
use uuid::Uuid;

use crate::service::{AuthorizedOutcome, GithubConnectService};

/// `GET /api/github/connect` — start the install flow.
pub async fn connect_github_handler(
    State(svc): State<Arc<GithubConnectService>>,
    axum::Extension(user_id): axum::Extension<Uuid>,
    headers: HeaderMap,
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

    // Bind the state to THIS browser: both callbacks require the cookie.
    let binding = BrowserBinding::for_request(&headers);
    match svc.begin_install(user_id, &binding).await {
        Ok(install_url) => (
            [binding.set_cookie_pair()],
            Json(serde_json::json!({
                "success": true,
                "install_url": install_url,
            })),
        )
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

/// `GET /api/github/installations` — list the user's connected installations
/// (for the Integrations UI). Authenticated; returns `{ installations: [...] }`.
pub async fn list_github_installations_handler(
    State(svc): State<Arc<GithubConnectService>>,
    axum::Extension(user_id): axum::Extension<Uuid>,
) -> impl IntoResponse {
    match svc.list_installations(user_id).await {
        Ok(installations) => Json(serde_json::json!({
            "success": true,
            "installations": installations,
        }))
        .into_response(),
        Err(e) => {
            tracing::error!(user_id = %user_id, error = %e, "GitHub App: list installations failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Failed to list GitHub installations",
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

/// `GET /api/github/setup` — the GitHub App Setup-URL callback. Redirects to
/// GitHub's user authorization; the installation is claimed at
/// `/api/github/authorized`, never here.
pub async fn github_setup_callback_handler(
    Query(params): Query<SetupParams>,
    State(svc): State<Arc<GithubConnectService>>,
    headers: HeaderMap,
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

    // The same browser continues into the second hop, so its binding is reused
    // for the next state (and the cookie's lifetime refreshed).
    let binding = BrowserBinding::for_request(&headers);
    match svc
        .handle_setup(
            params.installation_id.as_deref(),
            params.setup_action.as_deref(),
            &state,
            &binding,
            presented_connect_binding(&headers).as_deref(),
        )
        .await
    {
        Ok(authorize_url) => {
            ([binding.set_cookie_pair()], Redirect::to(&authorize_url)).into_response()
        }
        Err(e) => {
            // Generic code to the browser; full error server-side only.
            tracing::warn!(error = %e, "GitHub App setup callback failed");
            err_redirect("install_failed").into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizedParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// `GET /api/github/authorized` — the user-authorization callback (the App's
/// registered Callback URL). Claims the installation the setup step named, iff
/// GitHub lists it among the authorizing user's installations.
pub async fn github_authorized_callback_handler(
    Query(params): Query<AuthorizedParams>,
    State(svc): State<Arc<GithubConnectService>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let frontend_url = talos_config::get_frontend_url();
    let err_redirect = |code: &str| {
        Redirect::to(&format!(
            "{}/settings?github_error={}#integrations",
            frontend_url,
            urlencoding::encode(code)
        ))
    };

    if let Some(error) = params.error.as_deref() {
        tracing::warn!("GitHub user authorization returned an error");
        return err_redirect(talos_config::sanitize_oauth_error_code(error)).into_response();
    }
    let (code, state) = match (params.code.as_deref(), params.state.as_deref()) {
        (Some(c), Some(s)) if !c.is_empty() && !s.is_empty() => (c, s),
        _ => {
            tracing::warn!("GitHub user-authorization callback missing code or state");
            return err_redirect("missing_code_or_state").into_response();
        }
    };

    match svc
        .handle_authorized(code, state, presented_connect_binding(&headers).as_deref())
        .await
    {
        Ok(AuthorizedOutcome::Connected(outcome)) => {
            tracing::info!(account = %outcome.account_login, "GitHub App installation connected");
            Redirect::to(&format!(
                "{}/settings?github_connected={}#integrations",
                frontend_url,
                urlencoding::encode(&outcome.account_login)
            ))
            .into_response()
        }
        Ok(AuthorizedOutcome::Refused(refusal)) => {
            err_redirect(refusal.error_code()).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "GitHub user-authorization callback failed");
            err_redirect("install_failed").into_response()
        }
    }
}
