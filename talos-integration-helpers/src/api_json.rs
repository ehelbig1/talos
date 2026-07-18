//! JSON body extractor whose rejection is machine-readable.
//!
//! `axum::Json<T>`'s built-in rejection renders as PLAIN TEXT ("Failed
//! to deserialize the JSON body into the target type: …"), which breaks
//! every frontend that does an unconditional `res.json()` — the user
//! sees `Unexpected token 'F' … is not valid JSON` instead of the
//! actual problem (live bite: the GCP watch-create dialog with a
//! non-UUID module id, 2026-07-17). [`ApiJson`] wraps the same
//! extractor but maps the rejection into the integration crates'
//! `{"success": false, "data": null, "error": …}` envelope, so ALL
//! body-shape errors stay parseable.
//!
//! The rejection text is derived from the CALLER's own request body
//! (serde field/type messages), not from internal state — safe to echo.
//! Use this for every user-facing integration REST handler that takes a
//! JSON body; keep bare `axum::Json` for internal/machine-only routes
//! where the envelope shape doesn't apply.

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::response::{IntoResponse, Response};

pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                let status = rejection.status();
                let body = axum::Json(serde_json::json!({
                    "success": false,
                    "data": null,
                    "error": rejection.body_text(),
                }));
                Err((status, body).into_response())
            }
        }
    }
}
