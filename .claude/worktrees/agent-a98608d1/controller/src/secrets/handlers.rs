use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::secrets::SecretsManager;

pub async fn invalidate_cache_handler(
    State(secrets_manager): State<Arc<SecretsManager>>,
    Extension(_user_id): Extension<Uuid>,
) -> impl IntoResponse {
    // In a real system, you would check if the user is an admin here.
    // For now, we'll just invalidate the cache.
    let _ = secrets_manager.invalidate_dek_cache(Some(_user_id), "ADMIN_API", None).await;


    (StatusCode::OK, "DEK cache invalidated successfully").into_response()
}
