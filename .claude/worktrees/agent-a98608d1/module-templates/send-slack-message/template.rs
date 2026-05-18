use talos_sdk_macros::talos_module;
use serde_json::Value;

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
        use talos::core::logging::{self, Level};
        use talos::core::http::{Method, Request};

        let input_json: Value = serde_json::from_str(&input)
            .map_err(|e| format!("Invalid JSON input: {}", e))?;

        let config = input_json.get("config")
            .ok_or("Missing config")?;

        let bot_token = config.get("BOT_TOKEN")
            .and_then(|v| v.as_str())
            .ok_or("Missing BOT_TOKEN in config (set a secret reference)")?;

        let channel = config.get("CHANNEL")
            .and_then(|v| v.as_str())
            .ok_or("Missing CHANNEL in config")?;

        let text = config.get("TEXT")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let blocks = config.get("BLOCKS").cloned();

        logging::log(Level::Info, &format!("Sending Slack message to channel {}", channel));

        // Build payload — include blocks only when provided.
        let mut payload = serde_json::json!({
            "channel": channel,
            "text": text,
        });

        if let Some(b) = blocks {
            payload["blocks"] = b;
        }

        let body = serde_json::to_vec(&payload)
            .map_err(|e| format!("Failed to serialize payload: {}", e))?;

        let req = Request {
            method: Method::Post,
            url: "https://slack.com/api/chat.postMessage".to_string(),
            headers: vec![
                // SECURITY: never log the token value; log HTTP status only.
                ("Authorization".to_string(), format!("Bearer {}", bot_token)),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body,
            timeout_ms: Some(10_000),
        };

        let resp = talos::core::http::fetch(&req)
            .map_err(|e| format!("HTTP request failed: {:?}", e))?;

        logging::log(Level::Info, &format!("Slack API returned HTTP {}", resp.status));

        if resp.status != 200 {
            return Err(format!("Slack API returned HTTP {}", resp.status));
        }

        let body_str = String::from_utf8(resp.body)
            .map_err(|_| "Invalid UTF-8 in Slack API response".to_string())?;
        let response: Value = serde_json::from_str(&body_str)
            .map_err(|e| format!("Failed to parse Slack API response: {}", e))?;

        if !response.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            let error = response.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return Err(format!("Slack API error: {}", error));
        }

        let output = serde_json::json!({
            "success": true,
            "channel": channel,
            "ts": response.get("ts").cloned().unwrap_or(serde_json::json!(null)),
            "message": response.get("message").cloned().unwrap_or(serde_json::json!(null)),
        });

        serde_json::to_string(&output)
            .map_err(|e| format!("Failed to serialize output: {}", e))
    }
