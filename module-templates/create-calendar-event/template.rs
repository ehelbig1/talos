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

        // ACCESS_TOKEN is resolved from secrets by the controller before WASM execution.
        // SECURITY: never log the token value.
        let access_token = config.get("ACCESS_TOKEN")
            .and_then(|v| v.as_str())
            .ok_or("Missing ACCESS_TOKEN in config (set a secret reference)")?;

        let calendar_id = config.get("CALENDAR_ID")
            .and_then(|v| v.as_str())
            .unwrap_or("primary");

        let summary = config.get("SUMMARY")
            .and_then(|v| v.as_str())
            .ok_or("Missing SUMMARY in config")?;

        let start_time = config.get("START_TIME")
            .and_then(|v| v.as_str())
            .ok_or("Missing START_TIME in config (RFC 3339, e.g. 2024-01-15T09:00:00Z)")?;

        let end_time = config.get("END_TIME")
            .and_then(|v| v.as_str())
            .ok_or("Missing END_TIME in config (RFC 3339, e.g. 2024-01-15T10:00:00Z)")?;

        let description = config.get("DESCRIPTION")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let timezone = config.get("TIMEZONE")
            .and_then(|v| v.as_str())
            .unwrap_or("UTC");

        logging::log(Level::Info, &format!("Creating calendar event: {}", summary));

        let event_body = serde_json::json!({
            "summary": summary,
            "description": description,
            "start": {
                "dateTime": start_time,
                "timeZone": timezone,
            },
            "end": {
                "dateTime": end_time,
                "timeZone": timezone,
            },
        });

        let body = serde_json::to_vec(&event_body)
            .map_err(|e| format!("Failed to serialize event body: {}", e))?;

        // Percent-encode the calendar ID as a URL path segment (RFC 3986 §3.3).
        // `percent_encode` covers all reserved characters including '@', '/', '?', '#', ' ', etc.
        // The previous `.replace('@', "%40")` was incomplete.
        let encoded_cal = urlencoding::encode(calendar_id);
        let url = format!(
            "https://www.googleapis.com/calendar/v3/calendars/{}/events",
            encoded_cal
        );

        let req = Request {
            method: Method::Post,
            url,
            headers: vec![
                ("Authorization".to_string(), format!("Bearer {}", access_token)),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body,
            timeout_ms: Some(15_000),
        };

        let resp = talos::core::http::fetch(&req)
            .map_err(|e| format!("HTTP request failed: {:?}", e))?;

        logging::log(Level::Info, &format!("Google Calendar API returned HTTP {}", resp.status));

        // 200 or 201 are both success for event creation.
        if resp.status != 200 && resp.status != 201 {
            return Err(format!("Google Calendar API returned HTTP {}", resp.status));
        }

        let body_str = String::from_utf8(resp.body)
            .map_err(|_| "Invalid UTF-8 in Calendar API response".to_string())?;
        let created: Value = serde_json::from_str(&body_str)
            .map_err(|e| format!("Failed to parse Calendar API response: {}", e))?;

        let output = serde_json::json!({
            "success": true,
            "event_id": created.get("id").cloned().unwrap_or(serde_json::json!(null)),
            "html_link": created.get("htmlLink").cloned().unwrap_or(serde_json::json!(null)),
            "status": created.get("status").cloned().unwrap_or(serde_json::json!(null)),
            "summary": summary,
            "start_time": start_time,
            "end_time": end_time,
        });

        serde_json::to_string(&output)
            .map_err(|e| format!("Failed to serialize output: {}", e))
    }
