//! `GET /memory-grants/document`: the one document a memory read grant
//! reads.
//!
//! The request carries a bearer token and nothing else. Which actor and
//! which key it reads were fixed when the owner minted the grant
//! (`talos_actor_memory_service::read_grants`), so there is no parameter here
//! to widen. Everything that is not "this token reads a stored document" is
//! one `404` with one body: an unknown, malformed, expired, revoked or
//! used-up token, a token sent anywhere but the `Authorization` header, and
//! a key with nothing stored under it. A holder learns nothing about what
//! else exists.
//!
//! The token is read from the header only. A token in a URL is recorded by
//! proxies, tunnels and access logs; this one is never in a URL.

use axum::{
    extract::Extension,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use sqlx::{Pool, Postgres};
use talos_actor_memory_service::read_grants;

fn no_store(status: StatusCode, body: serde_json::Value) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

/// The one answer for every request that reads nothing.
fn nothing_to_read() -> Response {
    no_store(
        StatusCode::NOT_FOUND,
        serde_json::json!({ "error": "No document for this grant" }),
    )
}

/// Read the document a grant's token reads.
pub async fn memory_grant_read(
    Extension(db_pool): Extension<Pool<Postgres>>,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let Some(token) = read_grants::bearer_token(authorization) else {
        return nothing_to_read();
    };
    match read_grants::read_granted_document(&db_pool, token).await {
        Ok(Some(document)) => no_store(
            StatusCode::OK,
            serde_json::json!({
                "key": document.key,
                "value": document.value,
                "memory_type": document.memory_type,
                "updated_at": document.updated_at.to_rfc3339(),
            }),
        ),
        Ok(None) => nothing_to_read(),
        Err(e) => {
            // Neither the token nor the key is in this line.
            tracing::error!(error = %e, "memory grant read failed");
            no_store(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({ "error": "Temporarily unavailable" }),
            )
        }
    }
}
