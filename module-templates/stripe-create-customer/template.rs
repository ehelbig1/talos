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
    // Validates Stripe resource IDs before embedding in URL path segments.
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
    // Parses the Stripe error message from a non-2xx response body.
    // Stripe wraps errors under {"error": {"message": "...", "type": "...", "code": "..."}}
    fn extract_api_error(body: &str, status: u16) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|j| {
                j.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| format!("HTTP {}", status))
    }

    // ── URL encoding ──────────────────────────────────────────────────────────
    // Percent-encodes all bytes except unreserved chars (RFC 3986 §2.3).
    // Spaces become %20, NOT '+'. Used for application/x-www-form-urlencoded
    // bodies sent to the Stripe API.
    fn url_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                _ => {
                    out.push('%');
                    out.push(char::from_digit((byte >> 4) as u32, 16).unwrap().to_ascii_uppercase());
                    out.push(char::from_digit((byte & 0xf) as u32, 16).unwrap().to_ascii_uppercase());
                }
            }
        }
        out
    }

    // ── Form body builder ─────────────────────────────────────────────────────
    // Joins key=value pairs with '&', percent-encoding both sides.
    // Returns a Vec<u8> ready to use as the HTTP request body.
    fn build_form(params: &[(String, String)]) -> Vec<u8> {
        params
            .iter()
            .enumerate()
            .fold(String::new(), |mut acc, (i, (k, v))| {
                if i > 0 { acc.push('&'); }
                acc.push_str(&url_encode(k));
                acc.push('=');
                acc.push_str(&url_encode(v));
                acc
            })
            .into_bytes()
    }

    // ── Required config ───────────────────────────────────────────────────────
    let api_key_secret = config
        .get("API_KEY_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("API_KEY_SECRET is required (vault path to your Stripe secret key)")?;

    let email_raw = config
        .get("EMAIL")
        .and_then(|v| v.as_str())
        .ok_or("EMAIL is required")?;
    let email = interpolate(email_raw, &input_json);

    // ── Email validation ──────────────────────────────────────────────────────
    // Prevent CRLF injection and validate basic email structure.
    if email.contains('\n') || email.contains('\r') {
        return Err("EMAIL must not contain newline characters".to_string());
    }
    if !email.contains('@') || email.len() > 254 {
        return Err("Invalid email format: must contain '@' and be at most 254 characters".to_string());
    }

    // ── Retrieve API key from secret vault ────────────────────────────────────
    // SECURITY: never log the key value — only log its presence.
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Stripe secret key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "stripe-create-customer: API key retrieved");

    // ── Optional config ───────────────────────────────────────────────────────
    let name = config
        .get("NAME")
        .and_then(|v| v.as_str())
        .map(|raw| interpolate(raw, &input_json));

    let phone = config
        .get("PHONE")
        .and_then(|v| v.as_str())
        .map(|raw| interpolate(raw, &input_json));

    let description = config
        .get("DESCRIPTION")
        .and_then(|v| v.as_str())
        .map(|raw| interpolate(raw, &input_json));

    let metadata_str = config
        .get("METADATA")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    // ── Phone validation ──────────────────────────────────────────────────────
    if let Some(p) = &phone {
        if !p.is_empty() && !p.starts_with('+') {
            return Err("PHONE must be in E.164 format starting with '+' (e.g. '+15555555555')".to_string());
        }
    }

    // ── Build form params ─────────────────────────────────────────────────────
    // Stripe POST bodies use application/x-www-form-urlencoded, not JSON.
    let mut params: Vec<(String, String)> = Vec::new();

    params.push(("email".to_string(), email.clone()));

    if let Some(n) = name {
        if !n.is_empty() {
            params.push(("name".to_string(), n));
        }
    }

    if let Some(p) = phone {
        if !p.is_empty() {
            params.push(("phone".to_string(), p));
        }
    }

    if let Some(d) = description {
        if !d.is_empty() {
            params.push(("description".to_string(), d));
        }
    }

    // ── Metadata encoding ─────────────────────────────────────────────────────
    // Stripe accepts metadata as metadata[key]=value form params.
    // Keys: max 40 chars. Values: max 500 chars. Max 50 keys per object.
    if let Some(meta_str) = metadata_str {
        let meta: serde_json::Value = serde_json::from_str(meta_str)
            .map_err(|_| "METADATA must be a valid JSON object (e.g. '{\"user_id\": \"usr_123\"}')")?;
        let meta_obj = meta.as_object()
            .ok_or("METADATA must be a JSON object, not an array or scalar")?;
        if meta_obj.len() > 50 {
            return Err("METADATA must not contain more than 50 keys (Stripe limit)".to_string());
        }
        for (k, v) in meta_obj {
            if k.len() > 40 {
                return Err(format!(
                    "METADATA key '{}' exceeds maximum length of 40 characters",
                    k
                ));
            }
            let val_string = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "null".to_string(),
                other => other.to_string(),
            };
            if val_string.len() > 500 {
                return Err(format!(
                    "METADATA value for key '{}' exceeds maximum length of 500 characters",
                    k
                ));
            }
            params.push((format!("metadata[{}]", k), val_string));
        }
    }

    // ── HTTP POST request ─────────────────────────────────────────────────────
    talos::core::logging::log(Level::Info, "stripe-create-customer: creating customer");

    let body_bytes = build_form(&params);

    let response = talos::core::http::fetch(&Request {
        method: Method::Post,
        url: "https://api.stripe.com/v1/customers".to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Authorization".to_string(), format!("Bearer {}", api_key)),
            ("Stripe-Version".to_string(), "2024-12-18".to_string()),
        ],
        body: body_bytes,
        timeout_ms: Some(15000),
    })
    .map_err(|e| format!("HTTP request to Stripe failed: {:?}", e))?;

    // ── Response handling ─────────────────────────────────────────────────────
    // Cap response size to prevent unbounded memory allocation from large responses.
    const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MB
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Stripe API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body)
        .map_err(|_| "Invalid UTF-8 in Stripe API response".to_string())?;

    if response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Stripe API response".to_string())?;

        // Stripe returns customer fields at the top level (not nested under "data").
        let id_present = resp_json.get("id").is_some();

        talos::core::logging::log(
            Level::Info,
            &format!("stripe-create-customer: customer created successfully (id present: {})", id_present),
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "customer_id": resp_json.get("id"),
            "email": resp_json.get("email"),
            "name": resp_json.get("name"),
            "phone": resp_json.get("phone"),
            "description": resp_json.get("description"),
            "created": resp_json.get("created"),
            "livemode": resp_json.get("livemode"),
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("stripe-create-customer: API error {}: {}", response.status, api_message),
        );
        Err(format!("Stripe API error ({}): {}", response.status, api_message))
    }
}
