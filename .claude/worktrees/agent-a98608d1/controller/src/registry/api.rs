use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct PublishTemplateReq {
    pub name: String,
    pub category: String,
    pub description: String,
    pub config_schema: serde_json::Value,
    pub oci_url: String,
    pub code_template: Option<String>,
}

#[derive(Serialize)]
pub struct PublishTemplateResp {
    pub success: bool,
    pub message: String,
}

pub fn registry_router() -> Router<Arc<super::ModuleRegistry>> {
    Router::new().route("/publish", post(publish_template))
}

async fn publish_template(
    State(registry): State<Arc<super::ModuleRegistry>>,
    Json(payload): Json<PublishTemplateReq>,
) -> impl IntoResponse {
    let result = sqlx::query(
        "INSERT INTO node_templates (name, category, description, config_schema, code_template, oci_url)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (name) DO UPDATE SET
             category = EXCLUDED.category,
             description = EXCLUDED.description,
             code_template  = EXCLUDED.code_template,
             config_schema  = EXCLUDED.config_schema,
             oci_url        = EXCLUDED.oci_url"
    )
    .bind(&payload.name)
    .bind(&payload.category)
    .bind(&payload.description)
    .bind(&payload.config_schema)
    .bind(payload.code_template.unwrap_or_else(|| "".to_string()))
    .bind(&payload.oci_url)
    .execute(&registry.db_pool)
    .await;

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(PublishTemplateResp {
                success: true,
                message: format!("Template '{}' published successfully.", payload.name),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(PublishTemplateResp {
                success: false,
                message: format!("Failed to publish template: {}", e),
            }),
        ),
    }
}
