use talos_sdk_macros::talos_module;
use serde_json::Value;

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};
    use talos::core::http::{Method, Request};

    let input_json: Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    let config = input_json.get("config").ok_or("Missing config")?;

    // INTEGRATION_KEY_SECRET is resolved from the secrets store by the controller before WASM execution.
    // The config key holds the resolved integration key at runtime.
    // SECURITY: never log the integration key — it allows triggering PagerDuty incidents.
    let integration_key = config
        .get("INTEGRATION_KEY_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("Missing INTEGRATION_KEY_SECRET in config (store the key in the dashboard at Settings → Secrets with key_path='pagerduty/integration_key', then set INTEGRATION_KEY_SECRET to that path)")?;

    // Validate that the key looks like a 32-char hex string (PagerDuty format).
    // This is a best-effort check to catch obvious misconfigurations early.
    if integration_key.len() != 32 || !integration_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("INTEGRATION_KEY must be a 32-character hex string from PagerDuty Events API v2".to_string());
    }

    let summary = config
        .get("SUMMARY")
        .and_then(|v| v.as_str())
        .ok_or("Missing SUMMARY in config")?;

    // Validate summary length — PagerDuty truncates at 1024 chars.
    if summary.len() > 1024 {
        return Err("SUMMARY must not exceed 1024 characters".to_string());
    }

    let action = config
        .get("ACTION")
        .and_then(|v| v.as_str())
        .unwrap_or("trigger");

    // Validate action to prevent unintended operations.
    match action {
        "trigger" | "acknowledge" | "resolve" => {}
        _ => return Err(format!("ACTION must be one of: trigger, acknowledge, resolve (got '{}')", action)),
    }

    let severity = config
        .get("SEVERITY")
        .and_then(|v| v.as_str())
        .unwrap_or("error");

    match severity {
        "critical" | "error" | "warning" | "info" => {}
        _ => return Err(format!("SEVERITY must be one of: critical, error, warning, info (got '{}')", severity)),
    }

    let source = config
        .get("SOURCE")
        .and_then(|v| v.as_str())
        .unwrap_or("talos-workflow");

    let dedup_key = config.get("DEDUP_KEY").and_then(|v| v.as_str());

    logging::log(
        Level::Info,
        &format!("Sending PagerDuty {} event: {}", action, summary),
    );

    let mut payload = serde_json::json!({
        "routing_key": integration_key,
        "event_action": action,
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": source,
        }
    });

    // dedup_key is required for acknowledge/resolve; optional for trigger.
    if let Some(key) = dedup_key {
        payload["dedup_key"] = serde_json::Value::String(key.to_string());
    }

    let body = serde_json::to_vec(&payload)
        .map_err(|e| format!("Failed to serialize payload: {}", e))?;

    let req = Request {
        method: Method::Post,
        url: "https://events.pagerduty.com/v2/enqueue".to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
        timeout_ms: Some(10_000),
    };

    let resp = talos::core::http::fetch(&req)
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;

    logging::log(
        Level::Info,
        &format!("PagerDuty Events API returned HTTP {}", resp.status),
    );

    if resp.status < 200 || resp.status >= 300 {
        let body_str = String::from_utf8(resp.body).unwrap_or_default();
        return Err(format!(
            "PagerDuty Events API returned HTTP {}: {}",
            resp.status, body_str
        ));
    }

    let body_str = String::from_utf8(resp.body)
        .map_err(|_| "Invalid UTF-8 in PagerDuty API response".to_string())?;
    let response: Value = serde_json::from_str(&body_str)
        .map_err(|e| format!("Failed to parse PagerDuty API response: {}", e))?;

    let output = serde_json::json!({
        "success": true,
        "action": action,
        "status": response.get("status").cloned().unwrap_or(serde_json::json!("success")),
        "dedup_key": response.get("dedup_key").cloned().unwrap_or(serde_json::json!(null)),
        "message": response.get("message").cloned().unwrap_or(serde_json::json!(null)),
    });

    serde_json::to_string(&output)
        .map_err(|e| format!("Failed to serialize output: {}", e))
}
