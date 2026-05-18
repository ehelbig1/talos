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
    // Validates Stripe resource IDs (cus_xxx, price_xxx) before embedding in form
    // bodies. Whitelist approach: only alphanumeric, hyphens, and underscores.
    // Rejects path-traversal characters and form-encoding metacharacters.
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

    // ── Stripe API error extraction ───────────────────────────────────────────
    // Stripe error shape: {"error": {"message": "...", "type": "...", "code": "..."}}
    fn extract_api_error(body: &str, status: u16) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|j| j.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| format!("HTTP {}", status))
    }

    // ── RFC 3986 URL encoding ─────────────────────────────────────────────────
    // Percent-encodes everything except RFC 3986 unreserved characters
    // (ALPHA / DIGIT / "-" / "." / "_" / "~"). Used for form field values
    // in application/x-www-form-urlencoded bodies.
    fn url_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
                | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
                other => {
                    out.push('%');
                    out.push(char::from_digit((other >> 4) as u32, 16).unwrap_or('0').to_ascii_uppercase());
                    out.push(char::from_digit((other & 0xf) as u32, 16).unwrap_or('0').to_ascii_uppercase());
                }
            }
        }
        out
    }

    // ── Form body builder ─────────────────────────────────────────────────────
    // Encodes a slice of (name, value) pairs into application/x-www-form-urlencoded.
    // Both name and value are percent-encoded with url_encode().
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
        .ok_or("API_KEY_SECRET is required")?;

    let success_url_raw = config
        .get("SUCCESS_URL")
        .and_then(|v| v.as_str())
        .ok_or("SUCCESS_URL is required")?;
    let success_url = interpolate(success_url_raw, &input_json);
    if !success_url.starts_with("https://") {
        return Err("SUCCESS_URL must start with https://".to_string());
    }

    let cancel_url_raw = config
        .get("CANCEL_URL")
        .and_then(|v| v.as_str())
        .ok_or("CANCEL_URL is required")?;
    let cancel_url = interpolate(cancel_url_raw, &input_json);
    if !cancel_url.starts_with("https://") {
        return Err("CANCEL_URL must start with https://".to_string());
    }

    // ── Mode ──────────────────────────────────────────────────────────────────
    let mode = config
        .get("MODE")
        .and_then(|v| v.as_str())
        .unwrap_or("payment");
    match mode {
        "payment" | "subscription" | "setup" => {}
        _ => return Err(format!(
            "MODE must be one of: payment, subscription, setup (got '{}')",
            mode
        )),
    }

    // ── Price ID (required for payment and subscription modes) ────────────────
    let price_id: String = config
        .get("PRICE_ID")
        .and_then(|v| v.as_str())
        .map(|raw| { let s = interpolate(raw, &input_json); s.trim().to_string() })
        .unwrap_or_default();

    if (mode == "payment" || mode == "subscription") && price_id.is_empty() {
        return Err("PRICE_ID is required for payment and subscription modes".to_string());
    }
    if !price_id.is_empty() {
        validate_id(&price_id, "PRICE_ID")?;
    }

    // ── Quantity ──────────────────────────────────────────────────────────────
    let quantity = config
        .get("QUANTITY")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    if quantity < 1 {
        return Err("QUANTITY must be at least 1".to_string());
    }

    // ── Customer ID (optional) ────────────────────────────────────────────────
    let customer_id: String = config
        .get("CUSTOMER_ID")
        .and_then(|v| v.as_str())
        .map(|raw| { let s = interpolate(raw, &input_json); s.trim().to_string() })
        .unwrap_or_default();
    if !customer_id.is_empty() {
        validate_id(&customer_id, "CUSTOMER_ID")?;
    }

    // ── Customer email (optional) ─────────────────────────────────────────────
    let customer_email: String = config
        .get("CUSTOMER_EMAIL")
        .and_then(|v| v.as_str())
        .map(|raw| { let s = interpolate(raw, &input_json); s.trim().to_string() })
        .unwrap_or_default();
    if !customer_email.is_empty() {
        // SECURITY: reject CRLF injection and enforce basic email format.
        if customer_email.contains('\n') || customer_email.contains('\r') {
            return Err("CUSTOMER_EMAIL must not contain newline characters".to_string());
        }
        if !customer_email.contains('@') || customer_email.len() > 254 {
            return Err("CUSTOMER_EMAIL has an invalid format (must contain '@', max 254 chars)".to_string());
        }
    }

    // ── Mutual exclusion: CUSTOMER_ID and CUSTOMER_EMAIL ──────────────────────
    if !customer_id.is_empty() && !customer_email.is_empty() {
        return Err("Provide either CUSTOMER_ID or CUSTOMER_EMAIL, not both".to_string());
    }

    // ── Retrieve API key from secret vault ────────────────────────────────────
    // SECURITY: never log the key value — log its presence only.
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Stripe API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "stripe-create-checkout-session: API key retrieved");

    // ── Build form parameters ─────────────────────────────────────────────────
    let mut params: Vec<(String, String)> = vec![
        ("mode".to_string(), mode.to_string()),
        ("success_url".to_string(), success_url.clone()),
        ("cancel_url".to_string(), cancel_url.clone()),
    ];

    // Line items — only added when a price_id is present (not for bare setup mode).
    if !price_id.is_empty() {
        params.push(("line_items[0][price]".to_string(), price_id.clone()));
        params.push(("line_items[0][quantity]".to_string(), quantity.to_string()));
    }

    // Customer association (mutually exclusive fields validated above).
    if !customer_id.is_empty() {
        params.push(("customer".to_string(), customer_id.clone()));
    }
    if !customer_email.is_empty() {
        params.push(("customer_email".to_string(), customer_email.clone()));
    }

    // ── Metadata ──────────────────────────────────────────────────────────────
    // Accepts a JSON object string; each top-level key becomes metadata[key]=value.
    // Metadata keys and values are subject to Stripe's 500-char-per-value limit.
    if let Some(meta_str) = config.get("METADATA").and_then(|v| v.as_str()) {
        let meta_str = meta_str.trim();
        if !meta_str.is_empty() {
            let meta: serde_json::Value = serde_json::from_str(meta_str)
                .map_err(|_| "METADATA must be a valid JSON object string (e.g. '{\"order_id\": \"ord_123\"}')")?;
            let obj = meta.as_object()
                .ok_or("METADATA must be a JSON object (not an array or scalar)")?;
            for (k, v) in obj {
                // Flatten each value to a string for the form body.
                let val_str = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => "null".to_string(),
                    other => other.to_string(),
                };
                params.push((format!("metadata[{}]", k), val_str));
            }
        }
    }

    // ── HTTP request ──────────────────────────────────────────────────────────
    talos::core::logging::log(
        Level::Info,
        &format!(
            "stripe-create-checkout-session: creating {} session",
            mode
        ),
    );

    let body_bytes = build_form(&params);

    let response = talos::core::http::fetch(&Request {
        method: Method::Post,
        url: "https://api.stripe.com/v1/checkout/sessions".to_string(),
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
    // Cap response size to prevent unbounded memory allocation.
    const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MB
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Stripe API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body)
        .map_err(|_| "Invalid UTF-8 in Stripe API response".to_string())?;

    if response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Stripe API response as JSON".to_string())?;

        talos::core::logging::log(
            Level::Info,
            "stripe-create-checkout-session: checkout session created successfully",
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "session_id": resp_json.get("id"),
            "checkout_url": resp_json.get("url"),
            "mode": resp_json.get("mode"),
            "status": resp_json.get("status"),
            "customer_id": resp_json.get("customer"),
            "customer_email": resp_json.get("customer_email"),
            "expires_at": resp_json.get("expires_at"),
            "livemode": resp_json.get("livemode"),
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!(
                "stripe-create-checkout-session: API error {}: {}",
                response.status, api_message
            ),
        );
        Err(format!("Stripe API error ({}): {}", response.status, api_message))
    }
}
