use talos_sdk_macros::talos_module;
use serde_json::{json, Value};

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
        use talos::core::logging::{self, Level};

        // Parse incoming webhook payload
        let input_json: Value = serde_json::from_str(&input)
            .map_err(|e| format!("Invalid JSON input: {}", e))?;

        // Extract config (injected by runtime)
        let config = input_json.get("config")
            .ok_or("Missing 'config' in input")?;

        // Extract actual webhook payload
        let payload = input_json.get("input")
            .ok_or("Missing 'input' (webhook payload)")?;

        // Get the event type
        let event_type = payload["type"]
            .as_str()
            .ok_or("Missing 'type' field in payload")?;

        match event_type {
            // Handle URL verification challenge (initial setup)
            "url_verification" => {
                let challenge = payload["challenge"]
                    .as_str()
                    .ok_or("Missing 'challenge' field in url_verification")?;

                Ok(json!({
                    "challenge": challenge
                }).to_string())
            }

            // Handle event callbacks
            "event_callback" => {
                // Verify token if configured
                if let Some(verification_token) = config.get("VERIFICATION_TOKEN").and_then(|v| v.as_str()) {
                    if !verification_token.is_empty() {
                        let token = payload["token"]
                            .as_str()
                            .ok_or("Missing 'token' field in event_callback")?;

                        if token != verification_token {
                            return Err("Invalid verification token".to_string());
                        }
                    }
                }

                // Extract the event
                let event = payload["event"]
                    .as_object()
                    .ok_or("Missing or invalid 'event' field")?;

                let inner_event_type = event.get("type")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing event type")?;

                // Filter by event types if specified
                if let Some(event_types) = config.get("EVENT_TYPES").and_then(|v| v.as_array()) {
                    if !event_types.is_empty() {
                        let allowed = event_types.iter().any(|et| et.as_str() == Some(inner_event_type));
                        if !allowed {
                            return Ok(json!({
                                "status": "filtered",
                                "reason": format!("Event type '{}' not in allowed list", inner_event_type)
                            }).to_string());
                        }
                    }
                }

                // Per-channel rate limiting via the state interface.
                // Config: RATE_LIMIT.enabled, RATE_LIMIT.max_per_minute, RATE_LIMIT.max_per_channel
                let channel_id = event.get("channel").and_then(|c| c.as_str());
                if !check_slack_rate_limit(config, channel_id) {
                    logging::log(Level::Warn, "Slack rate limit exceeded — dropping event");
                    return Ok(json!({
                        "status": "rate_limited",
                        "reason": "Slack-specific rate limit exceeded"
                    }).to_string());
                }

                // Extract common fields
                let mut result = json!({
                    "event_type": inner_event_type,
                    "team_id": payload["team_id"],
                    "event_id": payload["event_id"],
                    "event_time": payload["event_time"],
                });

                // Extract event-specific data
                match inner_event_type {
                    "message" | "message.channels" | "message.groups" | "message.im" | "message.mpim" => {
                        result["user"] = event.get("user").cloned().unwrap_or(Value::Null);
                        result["text"] = event.get("text").cloned().unwrap_or(Value::Null);
                        result["channel"] = event.get("channel").cloned().unwrap_or(Value::Null);
                        result["ts"] = event.get("ts").cloned().unwrap_or(Value::Null);
                        result["subtype"] = event.get("subtype").cloned().unwrap_or(Value::Null);
                        result["thread_ts"] = event.get("thread_ts").cloned().unwrap_or(Value::Null);
                        result["bot_id"] = event.get("bot_id").cloned().unwrap_or(Value::Null);
                        result["files"] = event.get("files").cloned().unwrap_or(Value::Null);
                    }
                    "app_mention" => {
                        result["user"] = event.get("user").cloned().unwrap_or(Value::Null);
                        result["text"] = event.get("text").cloned().unwrap_or(Value::Null);
                        result["channel"] = event.get("channel").cloned().unwrap_or(Value::Null);
                        result["ts"] = event.get("ts").cloned().unwrap_or(Value::Null);
                        result["thread_ts"] = event.get("thread_ts").cloned().unwrap_or(Value::Null);
                    }
                    "reaction_added" | "reaction_removed" => {
                        result["user"] = event.get("user").cloned().unwrap_or(Value::Null);
                        result["reaction"] = event.get("reaction").cloned().unwrap_or(Value::Null);
                        result["item"] = event.get("item").cloned().unwrap_or(Value::Null);
                    }
                    "file_created" | "file_shared" | "file_deleted" | "file_public" | "file_change" => {
                        result["user_id"] = event.get("user_id").cloned().unwrap_or(Value::Null);
                        result["file_id"] = event.get("file_id").cloned().unwrap_or(Value::Null);
                        result["file"] = event.get("file").cloned().unwrap_or(Value::Null);
                    }
                    "channel_created" | "channel_deleted" | "channel_rename" | "channel_archive" | "channel_unarchive" => {
                        result["channel"] = event.get("channel").cloned().unwrap_or(Value::Null);
                    }
                    "member_joined_channel" | "member_left_channel" => {
                        result["user"] = event.get("user").cloned().unwrap_or(Value::Null);
                        result["channel"] = event.get("channel").cloned().unwrap_or(Value::Null);
                    }
                    _ => {
                        // For unknown event types, include the full event
                        result["event_data"] = Value::Object(event.clone());
                    }
                }

                // Filter by channel if specified
                if let Some(channel_filter) = config.get("CHANNEL_FILTER").and_then(|v| v.as_array()) {
                    if !channel_filter.is_empty() {
                        if let Some(channel) = result["channel"].as_str() {
                            let allowed = channel_filter.iter().any(|cf| cf.as_str() == Some(channel));
                            if !allowed {
                                return Ok(json!({
                                    "status": "filtered",
                                    "reason": format!("Channel '{}' not in allowed list", channel)
                                }).to_string());
                            }
                        }
                    }
                }

                // Filter by user if specified
                if let Some(user_filter) = config.get("USER_FILTER").and_then(|v| v.as_array()) {
                    if !user_filter.is_empty() {
                        if let Some(user) = result["user"].as_str() {
                            let allowed = user_filter.iter().any(|uf| uf.as_str() == Some(user));
                            if !allowed {
                                return Ok(json!({
                                    "status": "filtered",
                                    "reason": format!("User '{}' not in allowed list", user)
                                }).to_string());
                            }
                        }
                    }
                }

                // Apply advanced message filters for message events
                if is_message_event(inner_event_type) {
                    let filters = MessageFilters::from_config(config);
                    if let Some(reason) = check_message_filters(&result, &filters) {
                        return Ok(json!({
                            "status": "filtered",
                            "reason": reason
                        }).to_string());
                    }
                }

                // Determine output format
                let output_format = config.get("OUTPUT_FORMAT")
                    .and_then(|v| v.as_str())
                    .unwrap_or("simplified");

                let final_result = match output_format {
                    "raw" => Value::Object(event.clone()),
                    "enriched" => {
                        // Enrichment via Slack Web API.
                        // BOT_TOKEN is resolved from secrets by the controller before WASM execution
                        // — it arrives in config["BOT_TOKEN"] as a plaintext string.
                        // SECURITY: never log the token value; log HTTP status codes only.
                        let bot_token = config.get("BOT_TOKEN")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        if !bot_token.is_empty() {
                            let enrich_cfg = config.get("ENRICH_EVENTS");
                            let include_user_profile = enrich_cfg
                                .and_then(|e| e.get("include_user_profile"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let include_channel_info = enrich_cfg
                                .and_then(|e| e.get("include_channel_info"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let include_thread_context = enrich_cfg
                                .and_then(|e| e.get("include_thread_context"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let resolve_mentions = enrich_cfg
                                .and_then(|e| e.get("resolve_mentions"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                            if include_user_profile {
                                if let Some(uid) = result["user"].as_str() {
                                    if let Some(profile) = slack_get_user(bot_token, uid) {
                                        result["user_profile"] = profile;
                                    } else {
                                        logging::log(Level::Warn, &format!("Could not fetch profile for user {}", uid));
                                    }
                                }
                            }

                            if include_channel_info {
                                if let Some(cid) = result["channel"].as_str() {
                                    if let Some(ch) = slack_get_channel(bot_token, cid) {
                                        result["channel_info"] = ch;
                                    } else {
                                        logging::log(Level::Warn, &format!("Could not fetch info for channel {}", cid));
                                    }
                                }
                            }

                            if include_thread_context {
                                if let (Some(cid), Some(tts)) =
                                    (result["channel"].as_str(), result["thread_ts"].as_str())
                                {
                                    if let Some(msgs) = slack_get_thread_replies(bot_token, cid, tts) {
                                        result["thread_messages"] = msgs;
                                    }
                                }
                            }

                            if resolve_mentions {
                                if let Some(text) = result["text"].as_str().map(String::from) {
                                    let resolved = resolve_user_mentions(bot_token, &text);
                                    result["text_with_resolved_mentions"] = Value::String(resolved);
                                }
                            }
                        }

                        result
                    }
                    _ => result, // "simplified" is default
                };

                logging::log(Level::Info, &format!("Processed Slack {} event", inner_event_type));
                Ok(final_result.to_string())
            }

            _ => {
                Err(format!("Unknown Slack event type: {}", event_type))
            }
        }
    }

struct MessageFilters {}
impl MessageFilters {
    fn from_config(_c: &serde_json::Value) -> Self { Self {} }
}
fn check_slack_rate_limit(_c: &serde_json::Value, _ch: Option<&str>) -> bool { true }
fn is_message_event(t: &str) -> bool { t == "message" }
fn check_message_filters(_r: &serde_json::Value, _f: &MessageFilters) -> Option<String> { None }
fn slack_get_user(_t: &str, _u: &str) -> Option<serde_json::Value> { None }
fn slack_get_channel(_t: &str, _c: &str) -> Option<serde_json::Value> { None }
fn slack_get_thread_replies(_t: &str, _c: &str, _ts: &str) -> Option<serde_json::Value> { None }
fn resolve_user_mentions(_t: &str, text: &str) -> String { text.to_string() }
