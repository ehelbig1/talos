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

    // ── Optional config ───────────────────────────────────────────────────────
    let include_prices = config.get("INCLUDE_PRICES").and_then(|v| v.as_bool()).unwrap_or(true);
    let include_stats = config.get("INCLUDE_STATS").and_then(|v| v.as_bool()).unwrap_or(true);
    let limit = config.get("LIMIT").and_then(|v| v.as_u64()).unwrap_or(100).max(1).min(100);

    // ── Retrieve API key from secret vault ────────────────────────────────────
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-list-premium-tiers: API key retrieved");

    // ── Build query string ────────────────────────────────────────────────────
    let mut params: Vec<String> = vec![format!("limit={}", limit)];
    if include_prices { params.push("expand[]=prices".to_string()); }
    if include_stats  { params.push("expand[]=stats".to_string());  }

    let url = format!(
        "https://api.beehiiv.com/v2/publications/{}/tiers?{}",
        publication_id,
        params.join("&")
    );

    talos::core::logging::log(
        Level::Info,
        &format!("beehiiv-list-premium-tiers: fetching tiers for publication {}", publication_id),
    );

    // ── HTTP request ──────────────────────────────────────────────────────────
    let response = talos::core::http::fetch(&Request {
        method: Method::Get,
        url,
        headers: vec![
            ("Authorization".to_string(), format!("Bearer {}", api_key)),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(10000),
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

        let data = resp_json.get("data").cloned().unwrap_or(serde_json::json!([]));
        let tier_count = data.as_array().map(|a| a.len()).unwrap_or(0);

        talos::core::logging::log(
            Level::Info,
            &format!("beehiiv-list-premium-tiers: found {} tiers", tier_count),
        );

        // Build a summary alongside the raw data to make downstream condition
        // logic easier without requiring JSON traversal in condition expressions.
        let tier_ids: Vec<serde_json::Value> = data.as_array()
            .map(|arr| arr.iter().filter_map(|t| t.get("id")).cloned().collect())
            .unwrap_or_default();

        // Compute total active subscriptions across all tiers (when stats expanded)
        let total_active: u64 = data.as_array()
            .map(|arr| arr.iter().filter_map(|t| {
                t.get("stats")
                    .and_then(|s| s.get("active_subscriptions"))
                    .and_then(|v| v.as_u64())
            }).sum())
            .unwrap_or(0);

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "tiers": data,
            "tier_count": tier_count,
            "tier_ids": tier_ids,
            "total_active_subscriptions": total_active,
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-list-premium-tiers: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
