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

    // ── Percent-encode a string for use in URL path segments ─────────────────
    // Encodes all bytes except RFC 3986 unreserved characters (A-Z a-z 0-9 - _ . ~).
    // Required for email addresses containing '@', '+', etc.
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

    let email_raw = config
        .get("EMAIL")
        .and_then(|v| v.as_str())
        .ok_or("EMAIL is required")?;
    let email = interpolate(email_raw, &input_json);

    // ── Input validation ──────────────────────────────────────────────────────
    if email.contains('\n') || email.contains('\r') {
        return Err("EMAIL must not contain newline characters".to_string());
    }
    if !email.contains('@') || email.len() > 254 {
        return Err("Invalid email format".to_string());
    }

    let not_found_behavior = config
        .get("NOT_FOUND_BEHAVIOR")
        .and_then(|v| v.as_str())
        .unwrap_or("return_null");

    // ── Retrieve API key from secret vault ────────────────────────────────────
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-get-subscriber: API key retrieved");

    // ── Build URL with optional expand query params ───────────────────────────
    let encoded_email = percent_encode(&email);
    let mut url = format!(
        "https://api.beehiiv.com/v2/publications/{}/subscriptions/by_email/{}",
        publication_id, encoded_email
    );

    if let Some(expand_str) = config.get("EXPAND").and_then(|v| v.as_str()) {
        // Allowlist validation prevents arbitrary query parameter injection
        let allowed = ["stats", "custom_fields", "tags"];
        let params: Vec<String> = expand_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| allowed.contains(s))
            .map(|f| format!("expand[]={}", f))
            .collect();
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
    }

    talos::core::logging::log(
        Level::Info,
        &format!("beehiiv-get-subscriber: looking up subscriber in publication {}", publication_id),
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
    // Cap response size to prevent unbounded memory allocation from large responses.
    const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MB
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Beehiiv API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body).unwrap_or_default();

    if response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Beehiiv API response".to_string())?;

        let data = resp_json.get("data").unwrap_or(&resp_json);

        talos::core::logging::log(Level::Info, "beehiiv-get-subscriber: subscriber found");

        // Build output with all available fields; expanded fields added if present
        let mut out = serde_json::json!({
            "found": true,
            "subscription_id": data.get("id"),
            "email": data.get("email"),
            "status": data.get("status"),
            "created": data.get("created"),
            "subscription_tier": data.get("subscription_tier"),
            "subscription_premium_tier_names": data.get("subscription_premium_tier_names"),
            "utm_source": data.get("utm_source"),
            "utm_medium": data.get("utm_medium"),
            "utm_campaign": data.get("utm_campaign"),
            "referring_site": data.get("referring_site"),
            "referral_code": data.get("referral_code"),
        });

        for field in &["custom_fields", "tags", "stats"] {
            if let Some(val) = data.get(field) {
                out[field] = val.clone();
            }
        }

        Ok(serde_json::to_string(&out).unwrap())
    } else if response.status == 404 {
        talos::core::logging::log(Level::Info, "beehiiv-get-subscriber: subscriber not found");

        if not_found_behavior == "error" {
            return Err(format!("Subscriber not found: {}", email));
        }

        Ok(serde_json::to_string(&serde_json::json!({
            "found": false,
            "subscription_id": null,
            "email": email,
            "status": null,
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-get-subscriber: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
