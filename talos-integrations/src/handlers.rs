use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    Extension, Json,
};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use super::provider_config::PROVIDERS;

/// Response for the `/api/integrations/providers` endpoint.
#[derive(Serialize)]
struct ProviderInfo {
    id: &'static str,
    display_name: &'static str,
    description: &'static str,
    icon: &'static str,
    color: &'static str,
    graphql_enum: &'static str,
    /// OAuth host allowlist — the frontend uses this to validate redirect URLs.
    oauth_hosts: &'static [&'static str],
    /// Whether this provider is configured (env vars set) on this server.
    configured: bool,
    /// REST API path for initiating the OAuth connect flow.
    connect_url: String,
}

/// Returns all registered integration providers with their display metadata
/// and configuration status. The frontend uses this to dynamically render
/// integration cards and validate OAuth redirect URLs — no frontend code
/// changes needed when adding a new provider.
///
/// This endpoint is intentionally public (no auth required) because it
/// only returns static metadata and boolean configuration status.
pub async fn providers_handler() -> impl IntoResponse {
    let providers: Vec<ProviderInfo> = PROVIDERS
        .iter()
        .map(|p| ProviderInfo {
            id: p.id,
            display_name: p.display_name,
            description: p.description,
            icon: p.icon,
            color: p.color,
            graphql_enum: p.graphql_enum,
            oauth_hosts: p.oauth_hosts,
            configured: p.is_configured(),
            connect_url: format!("/api/{}/connect", p.id),
        })
        .collect();

    (StatusCode::OK, Json(providers))
}

/// Serves the latest morning briefing as an HTML page.
/// Finds the most recent completed execution of any workflow named
/// "daily-morning-briefing" belonging to the authenticated user, extracts
/// the HTML output from the render-html node.
pub async fn latest_briefing_handler(
    Extension(db_pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    // MCP-680: SecretsManager extension required to decrypt
    // `output_data_enc` on encryption-enabled deploys. The controller
    // registers this layer on the briefing_routes router.
    Extension(secrets_manager): Extension<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
) -> impl IntoResponse {
    // 1. Find the briefing workflow
    let wf_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM workflows WHERE user_id = $1 AND name = 'daily-morning-briefing' LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&db_pool)
    .await
    .ok()
    .flatten();

    let wf_id = match wf_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Html(
                    "<h1>No briefing workflow found</h1>\
                     <p>Create a workflow named 'daily-morning-briefing' first.</p>"
                        .to_string(),
                ),
            )
                .into_response()
        }
    };

    // 2. Get latest completed execution output.
    //
    // MCP-680 (2026-05-13): pre-fix the SELECT projected
    // `output_data::text` and filtered `output_data IS NOT NULL`.
    // With output encryption enabled (production default), every
    // completed-execution row has `output_data = NULL` (ciphertext
    // lives in `output_data_enc + output_enc_key_id`). So the
    // handler returned 404 "No completed briefing found" for every
    // user on every encryption-enabled deploy, even though the
    // daily-morning-briefing workflow had been firing nightly.
    // Fix: SELECT all three columns, decrypt via the SecretsManager
    // Extension passed in from the controller (sibling of the
    // MCP-680 fixes in talos-module-repository,
    // talos-workflow-repository, and talos-analytics-repository).
    let row: Option<(
        Option<serde_json::Value>,
        Option<Vec<u8>>,
        Option<Uuid>,
    )> = sqlx::query_as(
        "SELECT output_data, output_data_enc, output_enc_key_id \
         FROM workflow_executions \
         WHERE workflow_id = $1 AND user_id = $2 AND status = 'completed' \
           AND (output_data IS NOT NULL OR output_data_enc IS NOT NULL) \
         ORDER BY completed_at DESC LIMIT 1",
    )
    .bind(wf_id)
    .bind(user_id)
    .fetch_optional(&db_pool)
    .await
    .ok()
    .flatten();

    let output_json: serde_json::Value = match row {
        Some((plaintext, enc_bytes, key_id)) => {
            match (enc_bytes, key_id) {
                (Some(bytes), Some(kid)) => {
                    match secrets_manager.decrypt_value_by_key(kid, &bytes).await {
                        Ok(s) => match serde_json::from_str(&s) {
                            Ok(v) => v,
                            Err(_) => {
                                tracing::warn!(
                                    "latest_briefing_handler: decrypted bytes were not valid JSON"
                                );
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Html("<h1>Failed to parse execution output</h1>".to_string()),
                                )
                                    .into_response();
                            }
                        },
                        Err(e) => {
                            tracing::warn!(
                                err = ?e,
                                "latest_briefing_handler: decrypt_value_by_key failed"
                            );
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Html(
                                    "<h1>Could not decrypt briefing output</h1>\
                                     <p>Check controller logs for the underlying error.</p>"
                                        .to_string(),
                                ),
                            )
                                .into_response();
                        }
                    }
                }
                _ => match plaintext {
                    Some(v) => v,
                    None => {
                        // Shouldn't reach: WHERE filter requires non-NULL.
                        return (
                            StatusCode::NOT_FOUND,
                            Html("<h1>No completed briefing found</h1>".to_string()),
                        )
                            .into_response();
                    }
                },
            }
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Html(
                    "<h1>No completed briefing found</h1>\
                     <p>Run the daily-morning-briefing workflow first.</p>"
                        .to_string(),
                ),
            )
                .into_response()
        }
    };

    // The output structure is: { "render-html": { "html": "..." } }
    let html = output_json
        .get("render-html")
        .and_then(|node| node.get("html"))
        .and_then(|h| h.as_str());

    match html {
        Some(html_content) => {
            // Sanitize the HTML to prevent XSS from external data sources
            // (e.g., email content, calendar events) that the briefing workflow
            // may have ingested. ammonia strips scripts, event handlers, and
            // other dangerous elements while preserving safe formatting.
            let clean_html = ammonia::Builder::new()
                .tags(std::collections::HashSet::from([
                    "h1",
                    "h2",
                    "h3",
                    "h4",
                    "h5",
                    "h6",
                    "p",
                    "br",
                    "hr",
                    "div",
                    "span",
                    "ul",
                    "ol",
                    "li",
                    "table",
                    "thead",
                    "tbody",
                    "tr",
                    "th",
                    "td",
                    "strong",
                    "em",
                    "b",
                    "i",
                    "u",
                    "a",
                    "img",
                    "blockquote",
                    "pre",
                    "code",
                    "section",
                    "article",
                    "header",
                    "footer",
                    "nav",
                    "main",
                    "details",
                    "summary",
                    "dl",
                    "dt",
                    "dd",
                    "figure",
                    "figcaption",
                    "sup",
                    "sub",
                    "mark",
                    "small",
                    "del",
                    "ins",
                    "abbr",
                    "time",
                ]))
                .link_rel(Some("noopener noreferrer"))
                .url_relative(ammonia::UrlRelative::Deny)
                .add_tag_attributes("a", &["href", "title"])
                .add_tag_attributes("img", &["src", "alt", "width", "height"])
                .add_tag_attributes("td", &["colspan", "rowspan"])
                .add_tag_attributes("th", &["colspan", "rowspan"])
                .add_tag_attributes("time", &["datetime"])
                .clean(html_content)
                .to_string();

            let mut response = Html(clean_html).into_response();
            // Strict CSP: no scripts at all (briefings are static HTML reports).
            // style-src 'unsafe-inline' retained for inline styles in briefing
            // templates; scripts are stripped by ammonia and blocked by CSP.
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("content-security-policy"),
                axum::http::header::HeaderValue::from_static(
                    "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'"
                ),
            );
            response
        }
        None => (
            StatusCode::NOT_FOUND,
            Html(
                "<h1>No HTML output found</h1>\
                 <p>The briefing workflow execution did not produce HTML output.</p>"
                    .to_string(),
            ),
        )
            .into_response(),
    }
}
