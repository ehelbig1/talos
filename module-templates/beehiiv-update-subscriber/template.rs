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
                                    None => {
                                        found = false;
                                        break;
                                    }
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
    // Validates Beehiiv resource IDs before embedding in URL path segments.
    // Whitelist: alphanumeric, hyphens, underscores — no path-traversal chars.
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

    // ── Comma-separated list parser ───────────────────────────────────────────
    // Splits "a,b, c" into ["a","b","c"] as a JSON array. Returns None if empty.
    fn parse_comma_list(raw: &str) -> Option<serde_json::Value> {
        let items: Vec<serde_json::Value> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::json!(s))
            .collect();
        if items.is_empty() { None } else { Some(serde_json::json!(items)) }
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

    let subscription_id_raw = config
        .get("SUBSCRIPTION_ID")
        .and_then(|v| v.as_str())
        .ok_or("SUBSCRIPTION_ID is required")?;
    let subscription_id = interpolate(subscription_id_raw, &input_json);
    validate_id(&subscription_id, "SUBSCRIPTION_ID").map_err(|e| {
        format!("{} — use '{{{{subscription_id}}}}' to pull from a preceding beehiiv-get-subscriber node", e)
    })?;

    // ── Retrieve API key from secret vault ────────────────────────────────────
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-update-subscriber: API key retrieved");

    // ── Build PATCH body ──────────────────────────────────────────────────────
    // Only include fields that are explicitly configured — partial updates only.
    let mut body = serde_json::json!({});

    // Unsubscribe flag — irreversible, so emit a clear audit log entry
    let unsubscribe = config
        .get("UNSUBSCRIBE")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if unsubscribe {
        talos::core::logging::log(
            Level::Info,
            &format!("beehiiv-update-subscriber: marking subscription {} as unsubscribed", subscription_id),
        );
        body["unsubscribe"] = serde_json::json!(true);
    }

    // Tier change
    if let Some(tier) = config.get("TIER").and_then(|v| v.as_str()) {
        if !tier.is_empty() {
            body["tier"] = serde_json::json!(tier);
        }
    }

    // Custom fields: accept JSON string or array value
    if let Some(cf_val) = config.get("CUSTOM_FIELDS") {
        if let Some(cf_str) = cf_val.as_str() {
            if !cf_str.is_empty() {
                match serde_json::from_str::<serde_json::Value>(cf_str) {
                    Ok(parsed) if parsed.is_array() => {
                        body["custom_fields"] = parsed;
                    }
                    _ => {
                        return Err(
                            "CUSTOM_FIELDS must be a JSON array of {name, value} objects".to_string(),
                        );
                    }
                }
            }
        } else if cf_val.is_array() {
            body["custom_fields"] = cf_val.clone();
        }
    }

    // Tag and automation operations — all use the same comma-list pattern
    for (config_key, body_field) in &[
        ("ADD_TAGS", "add_tags"),
        ("REMOVE_TAGS", "remove_tags"),
        ("AUTOMATION_IDS", "automation_ids"),
    ] {
        if let Some(raw) = config.get(*config_key).and_then(|v| v.as_str()) {
            if let Some(list) = parse_comma_list(raw) {
                body[*body_field] = list;
            }
        }
    }

    // ── HTTP PATCH request ────────────────────────────────────────────────────
    let url = format!(
        "https://api.beehiiv.com/v2/publications/{}/subscriptions/{}",
        publication_id, subscription_id
    );

    talos::core::logging::log(
        Level::Info,
        &format!("beehiiv-update-subscriber: patching subscription {}", subscription_id),
    );

    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    let response = talos::core::http::fetch(&Request {
        method: Method::Patch,
        url,
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), format!("Bearer {}", api_key)),
        ],
        body: body_bytes,
        timeout_ms: Some(15000),
    })
    .map_err(|e| format!("HTTP request to Beehiiv failed: {:?}", e))?;

    // ── Response handling ─────────────────────────────────────────────────────
    const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MB
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Beehiiv API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body).unwrap_or_default();

    if response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Beehiiv API response".to_string())?;

        let data = resp_json.get("data").unwrap_or(&resp_json);

        talos::core::logging::log(
            Level::Info,
            &format!("beehiiv-update-subscriber: subscription {} updated successfully", subscription_id),
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "subscription_id": data.get("id"),
            "email": data.get("email"),
            "status": data.get("status"),
            "subscription_tier": data.get("subscription_tier"),
        }))
        .unwrap())
    } else if response.status == 404 {
        Err(format!("Subscription not found: {}", subscription_id))
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-update-subscriber: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
