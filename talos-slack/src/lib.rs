// Slack integration functions are not exercised by the current tests.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

mod rate_limiter;

pub mod integration;
#[allow(unused_imports)]
pub use integration::{SlackIntegration, SlackIntegrationInfo, SlackIntegrationService};

pub mod handlers;
pub use handlers::{
    connect_slack_handler, create_app_handler, disconnect_integration_handler,
    get_integration_handler, list_integrations_handler, slack_callback_handler,
};

/// Slack API client for enrichment and browsing
pub struct SlackApiClient {
    http_client: reqwest::Client,
}

impl Default for SlackApiClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
pub struct SlackApiParams {
    pub bot_token: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SlackApiResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SlackApiClient {
    pub fn new() -> Self {
        // MCP-497: same hardened-build-or-fail discipline as MCP-471 /
        // MCP-496. The Slack API uses Bearer tokens; reqwest only
        // strips `Authorization` on CROSS-origin redirects, so a
        // same-origin redirect within slack.com that bounced to an
        // attacker-controlled subdomain would carry the bot token.
        Self {
            // MCP-1034: explicit connect_timeout — slack.com TCP-handshake
            // failure (rare but possible) fails fast on 5s rather than
            // holding the call for 10s.
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("SlackApiClient: failed to build hardened reqwest client"),
        }
    }

    /// List conversations (channels)
    pub async fn list_conversations(&self, bot_token: &str) -> Result<Value> {
        self.call_slack_api(
            "conversations.list",
            bot_token,
            &[("types", "public_channel,private_channel")],
        )
        .await
    }

    /// List users
    pub async fn list_users(&self, bot_token: &str) -> Result<Value> {
        self.call_slack_api("users.list", bot_token, &[]).await
    }

    /// Get user info
    pub async fn get_user_info(&self, bot_token: &str, user_id: &str) -> Result<Value> {
        self.call_slack_api("users.info", bot_token, &[("user", user_id)])
            .await
    }

    /// Get channel info
    pub async fn get_channel_info(&self, bot_token: &str, channel_id: &str) -> Result<Value> {
        self.call_slack_api("conversations.info", bot_token, &[("channel", channel_id)])
            .await
    }

    /// Get conversation history (for thread context)
    pub async fn get_conversation_history(
        &self,
        bot_token: &str,
        channel_id: &str,
        thread_ts: Option<&str>,
    ) -> Result<Value> {
        let mut params = vec![("channel", channel_id), ("limit", "10")];
        if let Some(ts) = thread_ts {
            params.push(("latest", ts));
        }

        self.call_slack_api("conversations.history", bot_token, &params)
            .await
    }

    /// Get thread replies
    pub async fn get_thread_replies(
        &self,
        bot_token: &str,
        channel_id: &str,
        thread_ts: &str,
    ) -> Result<Value> {
        self.call_slack_api(
            "conversations.replies",
            bot_token,
            &[("channel", channel_id), ("ts", thread_ts)],
        )
        .await
    }

    /// Create a Slack app using the Apps Manifest API
    /// Requires a user token with apps:write scope
    pub async fn create_app_from_manifest(
        &self,
        user_token: &str,
        manifest: Value,
    ) -> Result<Value> {
        let url = "https://slack.com/api/apps.manifest.create";

        let body = serde_json::json!({
            "manifest": manifest
        });

        let response = self
            .http_client
            .post(url)
            .bearer_auth(user_token)
            .json(&body)
            .send()
            .await
            .context("Failed to call Slack Apps Manifest API")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Slack API returned non-success status: {}",
                response.status()
            ));
        }

        let json: Value = response
            .json()
            .await
            .context("Failed to parse Slack API response")?;

        // Check if Slack API returned an error
        if json.get("ok") == Some(&Value::Bool(false)) {
            let error = json
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown");
            return Err(anyhow!("Slack API error: {}", error));
        }

        Ok(json)
    }

    /// Generate a Slack app manifest based on webhook configuration
    pub fn generate_manifest(
        &self,
        app_name: &str,
        description: &str,
        webhook_url: &str,
        event_types: &[String],
    ) -> Value {
        // Extract unique scopes needed for the event types
        let mut scopes = vec![
            "channels:read".to_string(),
            "users:read".to_string(),
            "channels:history".to_string(),
            "chat:write".to_string(),
        ];

        // Add event-specific scopes
        for event_type in event_types {
            if event_type.starts_with("message.") && !scopes.contains(&"chat:write".to_string()) {
                scopes.push("chat:write".to_string());
            }
            if (event_type == "reaction_added" || event_type == "reaction_removed")
                && !scopes.contains(&"reactions:read".to_string())
            {
                scopes.push("reactions:read".to_string());
            }
            if event_type.starts_with("file_") && !scopes.contains(&"files:read".to_string()) {
                scopes.push("files:read".to_string());
            }
        }

        serde_json::json!({
            "display_information": {
                "name": app_name,
                "description": description,
                "background_color": "#4A154B"
            },
            "features": {
                "bot_user": {
                    "display_name": app_name,
                    "always_online": true
                }
            },
            "oauth_config": {
                "scopes": {
                    "bot": scopes
                }
            },
            "settings": {
                "event_subscriptions": {
                    "request_url": webhook_url,
                    "bot_events": event_types
                },
                "interactivity": {
                    "is_enabled": false
                },
                "org_deploy_enabled": false,
                "socket_mode_enabled": false,
                "token_rotation_enabled": false
            }
        })
    }

    /// Generic Slack API call
    async fn call_slack_api(
        &self,
        method: &str,
        bot_token: &str,
        params: &[(&str, &str)],
    ) -> Result<Value> {
        let url = format!("https://slack.com/api/{}", method);

        let mut request = self.http_client.get(&url).bearer_auth(bot_token);

        for (key, value) in params {
            request = request.query(&[(key, value)]);
        }

        let response = request.send().await.context("Failed to call Slack API")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Slack API returned non-success status: {}",
                response.status()
            ));
        }

        let json: Value = response
            .json()
            .await
            .context("Failed to parse Slack API response")?;

        // Check if Slack API returned an error
        if json.get("ok") == Some(&Value::Bool(false)) {
            let error = json
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown");
            return Err(anyhow!("Slack API error: {}", error));
        }

        Ok(json)
    }

    /// Enrich a Slack event with additional API data
    pub async fn enrich_event(
        &self,
        bot_token: &str,
        event: &mut Value,
        enrichment_config: &EnrichmentConfig,
    ) -> Result<()> {
        let event_obj = event
            .as_object_mut()
            .ok_or_else(|| anyhow!("Event is not an object"))?;

        // Enrich user profile
        if enrichment_config.include_user_profile {
            if let Some(user_id) = event_obj.get("user").and_then(|u| u.as_str()) {
                match self.get_user_info(bot_token, user_id).await {
                    Ok(user_data) => {
                        if let Some(user_obj) = user_data.get("user") {
                            event_obj.insert("user_profile".to_string(), user_obj.clone());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch user profile for {}: {}", user_id, e);
                    }
                }
            }
        }

        // Enrich channel info
        if enrichment_config.include_channel_info {
            if let Some(channel_id) = event_obj.get("channel").and_then(|c| c.as_str()) {
                match self.get_channel_info(bot_token, channel_id).await {
                    Ok(channel_data) => {
                        if let Some(channel_obj) = channel_data.get("channel") {
                            event_obj.insert("channel_info".to_string(), channel_obj.clone());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch channel info for {}: {}", channel_id, e);
                    }
                }
            }
        }

        // Enrich thread context
        if enrichment_config.include_thread_context {
            if let Some(channel_id) = event_obj.get("channel").and_then(|c| c.as_str()) {
                if let Some(thread_ts) = event_obj.get("thread_ts").and_then(|t| t.as_str()) {
                    match self
                        .get_thread_replies(bot_token, channel_id, thread_ts)
                        .await
                    {
                        Ok(thread_data) => {
                            if let Some(messages) = thread_data.get("messages") {
                                event_obj.insert("thread_messages".to_string(), messages.clone());
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch thread context: {}", e);
                        }
                    }
                }
            }
        }

        // Resolve mentions
        if enrichment_config.resolve_mentions {
            if let Some(text) = event_obj
                .get("text")
                .and_then(|t| t.as_str())
                .map(String::from)
            {
                let resolved_text = self.resolve_user_mentions(bot_token, &text).await;
                event_obj.insert(
                    "text_with_resolved_mentions".to_string(),
                    Value::String(resolved_text),
                );
            }
        }

        Ok(())
    }

    /// Resolve user mentions in text (<@U123> -> @username)
    async fn resolve_user_mentions(&self, bot_token: &str, text: &str) -> String {
        let mut resolved = text.to_string();

        // MCP-1009 (2026-05-15): compile the mention regex once via
        // `LazyLock` instead of re-compiling on every Slack message
        // processed. Same defensive-perf shape as MCP-626
        // (`talos-auth::validate_email`) and MCP-506
        // (`talos-http-utils::sanitization::MASK_PATTERNS`):
        //
        //   1. **Perf**: pre-fix, every message hit `Regex::new(...)`
        //      which parses the AST and builds the regex-automata DFA.
        //      For a workflow processing thousands of inbound Slack
        //      messages per hour the cumulative cost is significant.
        //
        //   2. **Fail-closed compile**: pre-fix used
        //      `let Ok(re) = Regex::new(...) else { return resolved; }`
        //      which silently fell through to the un-resolved text on
        //      compile failure. The pattern is a static literal —
        //      compile failure is a build / dependency-upgrade bug,
        //      not a runtime condition, so the right posture is
        //      `.expect()` (panic at first use surfacing in tests +
        //      boot) rather than silently producing a wrong-looking
        //      message that operators can't distinguish from "no
        //      mentions found."
        static MENTION_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(r"<@([A-Z0-9]+)>")
                .expect("BUG: Slack user-mention regex must compile")
        });
        let re = &*MENTION_RE;
        let mut replacements = Vec::new();

        for cap in re.captures_iter(text) {
            if let Some(user_id) = cap.get(1) {
                let user_id_str = user_id.as_str();
                if let Ok(user_data) = self.get_user_info(bot_token, user_id_str).await {
                    if let Some(name) = user_data
                        .get("user")
                        .and_then(|u| u.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        replacements.push((cap[0].to_string(), format!("@{}", name)));
                    }
                }
            }
        }

        for (old, new) in replacements {
            resolved = resolved.replace(&old, &new);
        }

        resolved
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EnrichmentConfig {
    pub include_user_profile: bool,
    pub include_channel_info: bool,
    pub include_thread_context: bool,
    pub resolve_mentions: bool,
}

/// Axum handler for listing Slack channels
///
/// MCP-976 (2026-05-15): accepts POST with JSON body
/// (`{ "bot_token": "xoxb-..." }`) rather than GET with the token in
/// the URL query string. Two reasons:
/// (1) Wire-mismatch fix — the frontend at
///     `frontend/src/components/builder/SlackBrowser.tsx:78` has
///     always POSTed JSON to this endpoint with `credentials:
///     "include"`. Pre-fix the route was registered as `get(...)` +
///     `Query<SlackApiParams>` so every browser invocation returned
///     405 Method Not Allowed; the Slack channel/user picker has
///     been broken since the route landed.
/// (2) Secrets-in-URL hygiene — bot_token is a long-lived Slack
///     credential. As a GET query parameter it would surface in
///     nginx access logs, browser history, referer headers, and
///     any HTTP proxy between client and server. Moving it to a
///     POST body keeps it out of those routine logging surfaces.
///     Same class as the canonical "don't put secrets in URLs"
///     rule that already governs the GraphQL `Authorization`
///     header on /graphql.
pub async fn list_channels_handler(
    State(client): State<Arc<SlackApiClient>>,
    Json(params): Json<SlackApiParams>,
) -> impl IntoResponse {
    match client.list_conversations(&params.bot_token).await {
        Ok(data) => Json(SlackApiResponse {
            ok: true,
            data: Some(data),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // MCP-927 (2026-05-14): log server-side, generic to
            // client. Two Axum handlers in `src/lib.rs` (not
            // `src/handlers.rs`) that the MCP-923 sweep missed —
            // live at /api/slack/channels and /api/slack/users.
            // Slack API errors can include upstream response detail
            // (rate-limit specifics, channel-permission text).
            tracing::error!(error = %e, "Slack channels handler failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SlackApiResponse {
                    ok: false,
                    data: None,
                    error: Some("Failed to list Slack channels".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Axum handler for listing Slack users
///
/// MCP-976: sibling of list_channels_handler — POST + JSON body so
/// bot_token doesn't land in URL-routed log surfaces. Same fix
/// rationale at the channels handler above.
pub async fn list_users_handler(
    State(client): State<Arc<SlackApiClient>>,
    Json(params): Json<SlackApiParams>,
) -> impl IntoResponse {
    match client.list_users(&params.bot_token).await {
        Ok(data) => Json(SlackApiResponse {
            ok: true,
            data: Some(data),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // MCP-927: log server-side, generic to client. See list_channels_handler.
            tracing::error!(error = %e, "Slack users handler failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SlackApiResponse {
                    ok: false,
                    data: None,
                    error: Some("Failed to list Slack users".to_string()),
                }),
            )
                .into_response()
        }
    }
}
