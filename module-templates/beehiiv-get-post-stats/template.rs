use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    use talos::core::http::{Method, Request};
    use talos::core::logging::Level;

    // ── Template interpolation ────────────────────────────────────────────────
    fn interpolate(template: &str, ctx: &serde_json::Value) -> String {
        let mut result = template.to_string();
        let mut start = 0;
        loop {
            match result[start..].find("{{") {
                None => break,
                Some(rel_open) => {
                    let open = start + rel_open;
                    match result[open + 2..].find("}}") {
                        None => break,
                        Some(rel_close) => {
                            let close = open + 2 + rel_close;
                            let path = result[open + 2..close].trim();
                            let parts: Vec<&str> = path.split('.').collect();
                            let mut cur = ctx;
                            let mut found = true;
                            for part in &parts {
                                match cur.get(part) {
                                    Some(v) => cur = v,
                                    None => { found = false; break; }
                                }
                            }
                            if found {
                                let replacement = match cur {
                                    serde_json::Value::String(s) => s.clone(),
                                    serde_json::Value::Null => "null".to_string(),
                                    other => other.to_string(),
                                };
                                result.replace_range(open..close + 2, &replacement);
                                start = open + replacement.len();
                            } else {
                                start = close + 2;
                            }
                        }
                    }
                }
            }
        }
        result
    }

    // ── ID validation ─────────────────────────────────────────────────────────
    fn validate_id(id: &str, field_name: &str) -> Result<(), String> {
        if id.is_empty() {
            return Err(format!("{} must not be empty", field_name));
        }
        if id.len() > 128 {
            return Err(format!("{} exceeds maximum length of 128 characters", field_name));
        }
        if !id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_')) {
            return Err(format!(
                "{} contains invalid characters — expected alphanumeric, hyphens, and underscores only",
                field_name
            ));
        }
        Ok(())
    }

    // ── API error extraction ──────────────────────────────────────────────────
    fn extract_api_error(body: &str, status: u16) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|j| j.get("message").and_then(|m| m.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| format!("HTTP {}", status))
    }

    // ── Required config ───────────────────────────────────────────────────────
    let api_key_secret = config
        .get("API_KEY_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("API_KEY_SECRET is required")?;

    let publication_id_raw = config
        .get("PUBLICATION_ID")
        .and_then(|v| v.as_str())
        .ok_or("PUBLICATION_ID is required")?;
    let publication_id = interpolate(publication_id_raw, &input_json);
    validate_id(&publication_id, "PUBLICATION_ID")?;

    let post_id_raw = config
        .get("POST_ID")
        .and_then(|v| v.as_str())
        .ok_or("POST_ID is required")?;
    let post_id = interpolate(post_id_raw, &input_json);
    validate_id(&post_id, "POST_ID")?;

    // ── Threshold config for downstream condition branching ───────────────────
    // Stored as f64 (0.0–1.0). Zero means "no threshold check".
    let open_rate_threshold = config
        .get("LOW_OPEN_RATE_THRESHOLD")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let click_rate_threshold = config
        .get("LOW_CLICK_RATE_THRESHOLD")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // ── Retrieve API key from secret vault ────────────────────────────────────
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-get-post-stats: API key retrieved");

    // ── HTTP request — always expand stats ───────────────────────────────────
    let url = format!(
        "https://api.beehiiv.com/v2/publications/{}/posts/{}?expand[]=stats",
        publication_id, post_id
    );

    talos::core::logging::log(
        Level::Info,
        &format!("beehiiv-get-post-stats: fetching stats for post {}", post_id),
    );

    let response = talos::core::http::fetch(&Request {
        method: Method::Get,
        url,
        headers: vec![
            ("Authorization".to_string(), format!("Bearer {}", api_key)),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(15000),
    })
    .map_err(|e| format!("HTTP request to Beehiiv failed: {:?}", e))?;

    // ── Response handling ─────────────────────────────────────────────────────
    const MAX_RESPONSE_BYTES: usize = 1_048_576;
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Beehiiv API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body).unwrap_or_default();

    if response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Beehiiv API response".to_string())?;

        let data = resp_json.get("data").unwrap_or(&resp_json);
        let stats = data.get("stats").cloned().unwrap_or(serde_json::json!({}));

        // Extract key metrics as top-level fields for easy condition branching
        let open_rate = stats.get("open_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let click_rate = stats.get("click_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let recipients = stats.get("recipients").and_then(|v| v.as_u64()).unwrap_or(0);
        let delivered = stats.get("delivered").and_then(|v| v.as_u64()).unwrap_or(0);
        let opens = stats.get("opens").and_then(|v| v.as_u64()).unwrap_or(0);
        let clicks = stats.get("clicks").and_then(|v| v.as_u64()).unwrap_or(0);
        let unsubscribes = stats.get("unsubscribes").and_then(|v| v.as_u64()).unwrap_or(0);
        let spam_reports = stats.get("spam_reports").and_then(|v| v.as_u64()).unwrap_or(0);

        // Compute delivery rate as a convenience metric
        let delivery_rate = if recipients > 0 {
            (delivered as f64) / (recipients as f64)
        } else {
            0.0
        };

        // Threshold flags for downstream condition nodes
        // Only set to true when a non-zero threshold is configured and the metric falls below it
        let below_open_rate_threshold = open_rate_threshold > 0.0 && open_rate < open_rate_threshold;
        let below_click_rate_threshold = click_rate_threshold > 0.0 && click_rate < click_rate_threshold;

        talos::core::logging::log(
            Level::Info,
            &format!(
                "beehiiv-get-post-stats: post {} — {} recipients, {:.1}% open rate, {:.1}% click rate",
                post_id,
                recipients,
                open_rate * 100.0,
                click_rate * 100.0
            ),
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "post_id": data.get("id"),
            "title": data.get("title"),
            "status": data.get("status"),
            "web_url": data.get("web_url"),
            "publish_date": data.get("publish_date"),
            // Flat metrics for easy condition-node access
            "recipients": recipients,
            "delivered": delivered,
            "opens": opens,
            "clicks": clicks,
            "unsubscribes": unsubscribes,
            "spam_reports": spam_reports,
            "open_rate": open_rate,
            "click_rate": click_rate,
            "delivery_rate": delivery_rate,
            // Threshold flags — only meaningful when thresholds are configured
            "below_open_rate_threshold": below_open_rate_threshold,
            "below_click_rate_threshold": below_click_rate_threshold,
            // Full stats object for advanced downstream use
            "stats": stats,
        }))
        .unwrap())
    } else if response.status == 404 {
        Err(format!("Post not found: {}", post_id))
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-get-post-stats: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
