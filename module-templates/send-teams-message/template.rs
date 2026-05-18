use talos_sdk_macros::talos_module;
use serde_json::Value;

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};
    use talos::core::http::{Method, Request};

    let input_json: Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    let config = input_json.get("config").ok_or("Missing config")?;

    // WEBHOOK_URL_SECRET is resolved from the secrets store by the controller before WASM execution.
    // The config key holds the resolved webhook URL at runtime.
    // SECURITY: never log the webhook URL — it grants write access to the channel.
    let webhook_url = config
        .get("WEBHOOK_URL_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("Missing WEBHOOK_URL_SECRET in config (store the webhook URL in the dashboard at Settings → Secrets with key_path='teams/webhook_url', then set WEBHOOK_URL_SECRET to that path)")?;

    // Validate URL scheme to prevent SSRF — only HTTPS allowed.
    if !webhook_url.starts_with("https://") {
        return Err("WEBHOOK_URL must use HTTPS".to_string());
    }

    // Validate against allowed hosts (outlook.office.com / outlook.office365.com).
    let allowed_hosts = ["outlook.office.com", "outlook.office365.com"];
    let is_allowed = allowed_hosts.iter().any(|h| {
        webhook_url
            .strip_prefix("https://")
            .map(|rest| rest.starts_with(h))
            .unwrap_or(false)
    });
    if !is_allowed {
        return Err("WEBHOOK_URL host is not an allowed Teams webhook host".to_string());
    }

    let title = config.get("TITLE").and_then(|v| v.as_str()).unwrap_or("");
    let text = config
        .get("TEXT")
        .and_then(|v| v.as_str())
        .unwrap_or("Talos notification");
    let color = config
        .get("COLOR")
        .and_then(|v| v.as_str())
        .unwrap_or("#0078D4");

    logging::log(Level::Info, "Sending Microsoft Teams message card");

    // Build an Adaptive Card payload compatible with Teams Incoming Webhooks.
    let payload = serde_json::json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": if title.is_empty() { text } else { title },
        "sections": [{
            "activityTitle": title,
            "activityText": text,
        }]
    });

    let body = serde_json::to_vec(&payload)
        .map_err(|e| format!("Failed to serialize payload: {}", e))?;

    let req = Request {
        method: Method::Post,
        url: webhook_url.to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
        timeout_ms: Some(10_000),
    };

    let resp = talos::core::http::fetch(&req)
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;

    logging::log(Level::Info, &format!("Teams webhook returned HTTP {}", resp.status));

    if resp.status < 200 || resp.status >= 300 {
        return Err(format!("Teams webhook returned HTTP {}", resp.status));
    }

    let output = serde_json::json!({
        "success": true,
        "status": resp.status,
    });

    serde_json::to_string(&output)
        .map_err(|e| format!("Failed to serialize output: {}", e))
}
