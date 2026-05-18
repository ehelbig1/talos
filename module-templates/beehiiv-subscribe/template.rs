use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    use talos::core::http::{Method, Request};
    use talos::core::logging::Level;

    // ── Template interpolation ────────────────────────────────────────────────
    // Replaces {{key}} and {{key.subkey}} in string values with upstream output.
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
    // Whitelist approach: only alphanumeric, hyphens, and underscores are safe.
    // Rejects '/', '?', '#', '%', '..' and other path-traversal/injection chars.
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
    // Parses the Beehiiv error message from a non-2xx response body.
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

    let email_raw = config
        .get("EMAIL")
        .and_then(|v| v.as_str())
        .ok_or("EMAIL is required")?;
    let email = interpolate(email_raw, &input_json);

    // ── Input validation ──────────────────────────────────────────────────────
    // Prevent CRLF injection and validate basic email structure.
    if email.contains('\n') || email.contains('\r') {
        return Err("EMAIL must not contain newline characters".to_string());
    }
    if !email.contains('@') || email.len() > 254 {
        return Err("Invalid email format".to_string());
    }

    // ── Retrieve API key from secret vault ────────────────────────────────────
    // Never log the key value — only log its presence.
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-subscribe: API key retrieved");

    // ── Optional config ───────────────────────────────────────────────────────
    let reactivate_existing = config
        .get("REACTIVATE_EXISTING")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let send_welcome_email = config
        .get("SEND_WELCOME_EMAIL")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // ── Build request body ────────────────────────────────────────────────────
    let mut body = serde_json::json!({
        "email": email,
        "reactivate_existing": reactivate_existing,
        "send_welcome_email": send_welcome_email,
    });

    // double_opt_override: only set when non-default
    if let Some(doi) = config.get("DOUBLE_OPT_OVERRIDE").and_then(|v| v.as_str()) {
        if doi != "not_set" {
            body["double_opt_override"] = serde_json::json!(doi);
        }
    }

    // Tier assignment
    if let Some(tier) = config.get("TIER").and_then(|v| v.as_str()) {
        if !tier.is_empty() {
            body["tier"] = serde_json::json!(tier);
        }
    }

    // UTM attribution — interpolate from upstream output if needed
    let utm_fields = [
        ("UTM_SOURCE", "utm_source"),
        ("UTM_MEDIUM", "utm_medium"),
        ("UTM_CAMPAIGN", "utm_campaign"),
        ("UTM_TERM", "utm_term"),
        ("UTM_CONTENT", "utm_content"),
    ];
    for (config_key, field_name) in &utm_fields {
        if let Some(raw) = config.get(*config_key).and_then(|v| v.as_str()) {
            let val = interpolate(raw, &input_json);
            if !val.is_empty() {
                body[*field_name] = serde_json::json!(val);
            }
        }
    }

    if let Some(raw) = config.get("REFERRING_SITE").and_then(|v| v.as_str()) {
        let val = interpolate(raw, &input_json);
        if !val.is_empty() {
            body["referring_site"] = serde_json::json!(val);
        }
    }

    if let Some(raw) = config.get("REFERRAL_CODE").and_then(|v| v.as_str()) {
        let val = interpolate(raw, &input_json);
        if !val.is_empty() {
            body["referral_code"] = serde_json::json!(val);
        }
    }

    // Custom fields: accept JSON string or array value
    let custom_fields_val = config.get("CUSTOM_FIELDS");
    if let Some(cf_val) = custom_fields_val {
        if let Some(cf_str) = cf_val.as_str() {
            if !cf_str.is_empty() {
                match serde_json::from_str::<serde_json::Value>(cf_str) {
                    Ok(parsed) if parsed.is_array() => {
                        body["custom_fields"] = parsed;
                    }
                    _ => {
                        return Err("CUSTOM_FIELDS must be a JSON array of {name, value} objects".to_string());
                    }
                }
            }
        } else if cf_val.is_array() {
            body["custom_fields"] = cf_val.clone();
        }
    }

    // Automation enrollment (comma-separated IDs)
    if let Some(ids_str) = config.get("AUTOMATION_IDS").and_then(|v| v.as_str()) {
        if let Some(ids) = parse_comma_list(ids_str) {
            body["automation_ids"] = ids;
        }
    }

    // ── HTTP request ──────────────────────────────────────────────────────────
    let url = format!(
        "https://api.beehiiv.com/v2/publications/{}/subscriptions",
        publication_id
    );

    talos::core::logging::log(Level::Info, &format!("beehiiv-subscribe: subscribing to publication {}", publication_id));

    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    let response = talos::core::http::fetch(&Request {
        method: Method::Post,
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
    // Cap response size to prevent unbounded memory allocation from large responses.
    const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MB
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Beehiiv API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body).unwrap_or_default();

    if response.status == 200 || response.status == 201 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Beehiiv API response".to_string())?;

        let data = resp_json.get("data").unwrap_or(&resp_json);

        talos::core::logging::log(Level::Info, "beehiiv-subscribe: subscription created/updated successfully");

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "subscription_id": data.get("id"),
            "email": data.get("email"),
            "status": data.get("status"),
            "created": data.get("created"),
            "subscription_tier": data.get("subscription_tier"),
            "utm_source": data.get("utm_source"),
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-subscribe: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
