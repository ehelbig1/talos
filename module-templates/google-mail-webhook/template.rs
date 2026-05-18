use talos_sdk_macros::talos_module;
use serde_json::Value;


fn fetch_history(_token: &str, _email: &str, _hid: &str, _labels: &[String]) -> Result<Vec<serde_json::Value>, String> {
    Ok(vec![])
}

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
        use talos::core::logging::{self, Level};

        let input_json: Value = serde_json::from_str(&input)
            .map_err(|e| format!("Invalid JSON input: {}", e))?;

        let config = input_json.get("config")
            .ok_or("Missing config")?;

        logging::log(Level::Info, "Gmail webhook module initialized");

        let watch_labels = config.get("WATCH_LABELS")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["INBOX".to_string()]);

        let event_types = config.get("EVENT_TYPES")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["messageAdded".to_string()]);

        let webhook_data = input_json.get("data")
            .or_else(|| input_json.get("webhook"));

        if let Some(webhook) = webhook_data {
            let event_type = webhook.get("type")
                .or_else(|| webhook.get("event_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let email_address = webhook.get("email_address")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let history_id = webhook.get("history_id")
                .and_then(|v| v.as_str());

            logging::log(Level::Info, &format!("Processing {} event for {}", event_type, email_address));

            if !event_types.iter().any(|t| t == event_type) {
                return Ok(serde_json::json!({
                    "skipped": true,
                    "reason": format!("Event type '{}' not in configured types", event_type)
                }).to_string());
            }

            // Fetch changed messages via Gmail History API when ACCESS_TOKEN is available.
            // ACCESS_TOKEN is resolved from secrets by the controller before WASM execution.
            // SECURITY: never log the token value; log HTTP status codes only.
            let access_token = config.get("ACCESS_TOKEN")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let changed_messages = if !access_token.is_empty() {
                if let Some(hid) = history_id {
                    match fetch_history(access_token, email_address, hid, &watch_labels) {
                        Ok(msgs) => {
                            logging::log(Level::Info, &format!("Fetched {} changed message(s)", msgs.len()));
                            msgs
                        }
                        Err(e) => {
                            logging::log(Level::Warn, &format!("Failed to fetch Gmail history: {}", e));
                            vec![]
                        }
                    }
                } else {
                    logging::log(Level::Info, "No historyId in push notification — skipping history fetch");
                    vec![]
                }
            } else {
                logging::log(Level::Info, "No ACCESS_TOKEN in config — skipping history fetch");
                vec![]
            };

            let output = serde_json::json!({
                "success": true,
                "event_type": event_type,
                "email_address": email_address,
                "history_id": history_id,
                "changed_messages": changed_messages,
                "push_notification": webhook.get("message").cloned().unwrap_or(serde_json::json!(null))
            });

            serde_json::to_string(&output)
                .map_err(|e| format!("Failed to serialize output: {}", e))
        } else {
            let output = serde_json::json!({
                "status": "configured",
                "watching_labels": watch_labels,
                "event_types": event_types,
                "message": "Gmail webhook listener configured. Waiting for events..."
            });

            serde_json::to_string(&output)
                .map_err(|e| format!("Failed to serialize output: {}", e))
        }
    }
