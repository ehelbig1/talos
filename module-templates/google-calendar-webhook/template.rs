use talos_sdk_macros::talos_module;
use serde_json::Value;

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};

    let input_json: Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    let config = input_json.get("config")
        .ok_or("Missing config")?;

    logging::log(Level::Info, "Google Calendar webhook module initialized");

    let calendar_ids = config.get("CALENDAR_IDS")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let event_types = config.get("EVENT_TYPES")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["created".to_string(), "updated".to_string()]);

    let webhook_data = input_json.get("data")
        .or_else(|| input_json.get("webhook"));

    if let Some(webhook) = webhook_data {
        let event_type = webhook.get("type")
            .or_else(|| webhook.get("event_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let calendar_id = webhook.get("organizer")
            .and_then(|o| o.get("email"))
            .and_then(|v| v.as_str())
            .unwrap_or("primary");

        logging::log(
            Level::Info,
            &format!("Processing {} event for calendar {}", event_type, calendar_id),
        );

        if !event_types.iter().any(|t| t == event_type) {
            return Ok(serde_json::json!({
                "skipped": true,
                "reason": format!("Event type '{}' not in configured types", event_type)
            }).to_string());
        }

        if !calendar_ids.is_empty()
            && !calendar_ids.iter().any(|c| c == calendar_id || calendar_id == "primary")
        {
            return Ok(serde_json::json!({
                "skipped": true,
                "reason": format!("Calendar '{}' not in watch list", calendar_id)
            }).to_string());
        }

        // The Controller has already fetched the event and passed it directly to us in `webhook_data`.
        // We do not need to call the Google API again from within the sandbox!
        // We just package it up for the downstream workflow nodes.
        let output = serde_json::json!({
            "success": true,
            "event_type": event_type,
            "calendar_id": calendar_id,
            "event": webhook,
            // Keeping these fields for backwards compatibility with downstream nodes
            "push_notification": webhook, 
            "changed_events": vec![webhook], 
        });

        serde_json::to_string(&output)
            .map_err(|e| format!("Failed to serialize output: {}", e))
    } else {
        let output = serde_json::json!({
            "status": "configured",
            "watching_calendars": calendar_ids,
            "event_types": event_types,
            "message": "Google Calendar webhook listener configured. Waiting for events..."
        });

        serde_json::to_string(&output)
            .map_err(|e| format!("Failed to serialize output: {}", e))
    }
}
