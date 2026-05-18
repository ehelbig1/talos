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

    let automation_id_raw = config
        .get("AUTOMATION_ID")
        .and_then(|v| v.as_str())
        .ok_or("AUTOMATION_ID is required")?;
    let automation_id = interpolate(automation_id_raw, &input_json);
    validate_id(&automation_id, "AUTOMATION_ID")?;

    // ── Subscriber identity — exactly one of SUBSCRIPTION_ID or EMAIL ─────────
    let sub_id_raw = config.get("SUBSCRIPTION_ID").and_then(|v| v.as_str()).map(|s| interpolate(s, &input_json));
    let email_raw = config.get("EMAIL").and_then(|v| v.as_str()).map(|s| interpolate(s, &input_json));

    let (sub_id, email) = match (sub_id_raw.filter(|s| !s.is_empty()), email_raw.filter(|s| !s.is_empty())) {
        (Some(id), None) => {
            validate_id(&id, "SUBSCRIPTION_ID")?;
            (Some(id), None)
        }
        (None, Some(em)) => {
            if em.contains('\n') || em.contains('\r') {
                return Err("EMAIL must not contain newline characters".to_string());
            }
            if !em.contains('@') || em.len() > 254 {
                return Err("Invalid email format".to_string());
            }
            (None, Some(em))
        }
        (Some(_), Some(_)) => return Err("Provide either SUBSCRIPTION_ID or EMAIL, not both".to_string()),
        (None, None) => return Err("Either SUBSCRIPTION_ID or EMAIL is required".to_string()),
    };

    // ── Optional config ───────────────────────────────────────────────────────
    let double_opt_override = config
        .get("DOUBLE_OPT_OVERRIDE")
        .and_then(|v| v.as_str())
        .unwrap_or("not_set");
    if !["on", "off", "not_set"].contains(&double_opt_override) {
        return Err(format!("DOUBLE_OPT_OVERRIDE must be 'on', 'off', or 'not_set', got '{}'", double_opt_override));
    }

    // ── Retrieve API key from secret vault ────────────────────────────────────
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-add-to-automation: API key retrieved");

    // ── Build request body ────────────────────────────────────────────────────
    let mut body = serde_json::json!({});
    if let Some(id) = &sub_id {
        body["subscription_id"] = serde_json::json!(id);
    }
    if let Some(em) = &email {
        body["email"] = serde_json::json!(em);
    }
    if double_opt_override != "not_set" {
        body["double_opt_override"] = serde_json::json!(double_opt_override);
    }

    // ── HTTP request ──────────────────────────────────────────────────────────
    let url = format!(
        "https://api.beehiiv.com/v2/publications/{}/automations/{}/journeys",
        publication_id, automation_id
    );

    talos::core::logging::log(
        Level::Info,
        &format!("beehiiv-add-to-automation: enrolling subscriber in automation {}", automation_id),
    );

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
    const MAX_RESPONSE_BYTES: usize = 1_048_576;
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Beehiiv API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body).unwrap_or_default();

    if response.status == 200 || response.status == 201 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Beehiiv API response".to_string())?;

        let data = resp_json.get("data").unwrap_or(&resp_json);

        talos::core::logging::log(
            Level::Info,
            &format!("beehiiv-add-to-automation: subscriber enrolled in automation {}", automation_id),
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "journey_id": data.get("id"),
            "automation_id": data.get("automation_id"),
            "subscription_id": data.get("subscription_id"),
            "email": data.get("email"),
            "status": data.get("status"),
            "started_at": data.get("started_at"),
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-add-to-automation: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
