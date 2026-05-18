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

    // ── Percent-encode for query string values ────────────────────────────────
    // Used for the cursor token which is an opaque base64-like string.
    fn percent_encode(s: &str) -> String {
        let mut encoded = String::new();
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    encoded.push('%');
                    let hi = byte >> 4;
                    let lo = byte & 0xF;
                    encoded.push(if hi < 10 { (b'0' + hi) as char } else { (b'A' + hi - 10) as char });
                    encoded.push(if lo < 10 { (b'0' + lo) as char } else { (b'A' + lo - 10) as char });
                }
            }
        }
        encoded
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

    // ── Retrieve API key from secret vault ────────────────────────────────────
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-list-subscribers: API key retrieved");

    // ── Validated optional filters ────────────────────────────────────────────
    let status = config.get("STATUS").and_then(|v| v.as_str()).unwrap_or("all");
    let allowed_statuses = ["all", "validating", "invalid", "pending", "active", "inactive"];
    if !allowed_statuses.contains(&status) {
        return Err(format!(
            "STATUS must be one of: {}, got '{}'",
            allowed_statuses.join(", "),
            status
        ));
    }

    let tier = config.get("TIER").and_then(|v| v.as_str()).unwrap_or("all");
    if !["all", "free", "premium"].contains(&tier) {
        return Err(format!("TIER must be 'all', 'free', or 'premium', got '{}'", tier));
    }

    let direction = config.get("DIRECTION").and_then(|v| v.as_str()).unwrap_or("desc");
    if !["asc", "desc"].contains(&direction) {
        return Err(format!("DIRECTION must be 'asc' or 'desc', got '{}'", direction));
    }

    // Limit: clamp to 1–100
    let limit = config
        .get("LIMIT")
        .and_then(|v| v.as_u64())
        .unwrap_or(25)
        .max(1)
        .min(100);

    let expand_stats = config.get("EXPAND_STATS").and_then(|v| v.as_bool()).unwrap_or(false);
    let expand_custom_fields = config.get("EXPAND_CUSTOM_FIELDS").and_then(|v| v.as_bool()).unwrap_or(false);

    // ── Build query string ────────────────────────────────────────────────────
    let mut params: Vec<String> = Vec::new();

    params.push(format!("limit={}", limit));
    params.push(format!("order_by=created"));
    params.push(format!("direction={}", direction));

    if status != "all" {
        params.push(format!("status={}", status));
    }
    if tier != "all" {
        params.push(format!("tier={}", tier));
    }

    // Premium tier ID filtering: each ID becomes a separate premium_tier_ids[] param
    if let Some(ids_str) = config.get("PREMIUM_TIER_IDS").and_then(|v| v.as_str()) {
        for raw_id in ids_str.split(',') {
            let id = raw_id.trim();
            if !id.is_empty() {
                validate_id(id, "PREMIUM_TIER_IDS entry")?;
                params.push(format!("premium_tier_ids[]={}", id));
            }
        }
    }

    // Expand fields
    if expand_stats {
        params.push("expand[]=stats".to_string());
    }
    if expand_custom_fields {
        params.push("expand[]=custom_fields".to_string());
    }

    // Cursor for pagination — opaque token, must be percent-encoded
    if let Some(cursor_raw) = config.get("CURSOR").and_then(|v| v.as_str()) {
        let cursor = interpolate(cursor_raw, &input_json);
        if !cursor.is_empty() && cursor != "null" {
            params.push(format!("cursor={}", percent_encode(&cursor)));
        }
    }

    let url = format!(
        "https://api.beehiiv.com/v2/publications/{}/subscriptions?{}",
        publication_id,
        params.join("&")
    );

    talos::core::logging::log(
        Level::Info,
        &format!(
            "beehiiv-list-subscribers: fetching subscribers (tier={}, status={}, limit={})",
            tier, status, limit
        ),
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
        timeout_ms: Some(20000),
    })
    .map_err(|e| format!("HTTP request to Beehiiv failed: {:?}", e))?;

    // ── Response handling ─────────────────────────────────────────────────────
    // Cap at 10 MB — a page of 100 subscribers with stats can be sizeable
    const MAX_RESPONSE_BYTES: usize = 10_485_760;
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Beehiiv API response body exceeds 10 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body).unwrap_or_default();

    if response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Beehiiv API response".to_string())?;

        let data = resp_json.get("data").cloned().unwrap_or(serde_json::json!([]));
        let subscriber_count = data.as_array().map(|a| a.len()).unwrap_or(0);
        let has_more = resp_json.get("has_more").and_then(|v| v.as_bool()).unwrap_or(false);
        let next_cursor = resp_json.get("next_cursor").cloned().unwrap_or(serde_json::json!(null));
        let total_results = resp_json.get("total_results").cloned().unwrap_or(serde_json::json!(null));

        talos::core::logging::log(
            Level::Info,
            &format!(
                "beehiiv-list-subscribers: fetched {} subscribers, has_more={}",
                subscriber_count, has_more
            ),
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "data": data,
            "count": subscriber_count,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "total_results": total_results,
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-list-subscribers: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
