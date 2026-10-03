//! The two HTTP handlers of the bank-connect flow, both behind session auth
//! and the cookie-session CSRF gate (they are POSTs from the web app).
//! Listing and disconnecting are the generic `serviceIntegrations` /
//! `disconnectServiceIntegration` paths, driven by the provider registry.

use super::{ConnectRefusal, Institution, PlaidConnectService};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct LinkTokenData {
    pub link_token: String,
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    pub public_token: String,
    #[serde(default)]
    pub institution_id: Option<String>,
    #[serde(default)]
    pub institution_name: Option<String>,
}

#[derive(Serialize)]
pub struct ConnectedData {
    pub institution_name: Option<String>,
    pub accounts: Option<usize>,
}

fn status_for(refusal: ConnectRefusal) -> StatusCode {
    match refusal {
        ConnectRefusal::NotConfigured => StatusCode::SERVICE_UNAVAILABLE,
        ConnectRefusal::BadPublicToken => StatusCode::BAD_REQUEST,
        ConnectRefusal::Exchange | ConnectRefusal::LinkToken => StatusCode::BAD_GATEWAY,
        ConnectRefusal::Store => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn refused<T: Serialize>(refusal: ConnectRefusal) -> axum::response::Response {
    (
        status_for(refusal),
        Json(ApiResponse::<T> {
            success: false,
            data: None,
            error: Some(refusal.message().to_string()),
        }),
    )
        .into_response()
}

/// `POST /api/plaid/link-token` — start a bank sign-in.
pub async fn link_token_handler(
    State(service): State<Arc<PlaidConnectService>>,
    Extension(user_id): Extension<Uuid>,
) -> axum::response::Response {
    match service.link_token(user_id).await {
        Ok(token) => Json(ApiResponse {
            success: true,
            data: Some(LinkTokenData {
                link_token: token.as_str().to_string(),
            }),
            error: None,
        })
        .into_response(),
        Err(r) => refused::<LinkTokenData>(r),
    }
}

/// `POST /api/plaid/connect` — finish a bank sign-in with Link's
/// `public_token`. The access token it yields is stored server-side and never
/// returned.
pub async fn connect_handler(
    State(service): State<Arc<PlaidConnectService>>,
    Extension(user_id): Extension<Uuid>,
    Json(body): Json<ConnectRequest>,
) -> axum::response::Response {
    let institution = Institution {
        id: body.institution_id,
        name: body.institution_name,
    };
    match service
        .connect(user_id, &body.public_token, institution)
        .await
    {
        Ok(item) => Json(ApiResponse {
            success: true,
            data: Some(ConnectedData {
                institution_name: item.institution_name,
                accounts: item.accounts,
            }),
            error: None,
        })
        .into_response(),
        Err(r) => refused::<ConnectedData>(r),
    }
}
