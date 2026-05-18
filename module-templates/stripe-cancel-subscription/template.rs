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
    // Stripe wraps errors as: {"error": {"message": "...", "type": "...", "code": "..."}}
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
    // Percent-encodes a string for use in application/x-www-form-urlencoded bodies.
    // Encodes all characters that are not unreserved (RFC 3986): A-Z a-z 0-9 - _ . ~
    // Space is encoded as %20 (not '+') for consistency with Stripe's form parser.
    fn url_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
                | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }

    // ── Form body builder ─────────────────────────────────────────────────────
    // Serializes a slice of (key, value) pairs into application/x-www-form-urlencoded
    // format: "key1=val1&key2=val2". Both keys and values are percent-encoded.
    fn build_form(pairs: &[(String, String)]) -> Vec<u8> {
        pairs
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

    let subscription_id_raw = config
        .get("SUBSCRIPTION_ID")
        .and_then(|v| v.as_str())
        .ok_or("SUBSCRIPTION_ID is required")?;
    let subscription_id = interpolate(subscription_id_raw, &input_json);
    validate_id(&subscription_id, "SUBSCRIPTION_ID").map_err(|e| {
        format!(
            "{} — use '{{{{subscription_id}}}}' to pull from a preceding node's output",
            e
        )
    })?;

    // ── Optional config ───────────────────────────────────────────────────────
    // CANCEL_AT_PERIOD_END: accepts bool or "true"/"false" string.
    let cancel_at_period_end = config
        .get("CANCEL_AT_PERIOD_END")
        .map(|v| {
            v.as_bool().unwrap_or_else(|| {
                v.as_str()
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    // ── Retrieve API key from secret vault ────────────────────────────────────
    // SECURITY: never log the key value — only log its presence.
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Stripe API key from '{}': {:?}", api_key_secret, e))?;

    // ── Audit log ─────────────────────────────────────────────────────────────
    talos::core::logging::log(
        Level::Info,
        &format!(
            "stripe-cancel-subscription: canceling subscription {} (at_period_end={})",
            subscription_id, cancel_at_period_end
        ),
    );

    // ── Build request ─────────────────────────────────────────────────────────
    let url = format!("https://api.stripe.com/v1/subscriptions/{}", subscription_id);

    let request = if cancel_at_period_end {
        // POST with form body — schedules cancellation at end of billing period.
        // Stripe requires application/x-www-form-urlencoded for POST updates.
        let body = build_form(&[("cancel_at_period_end".to_string(), "true".to_string())]);
        Request {
            method: Method::Post,
            url,
            headers: vec![
                ("Authorization".to_string(), format!("Bearer {}", api_key)),
                ("Stripe-Version".to_string(), "2024-12-18".to_string()),
                (
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ),
            ],
            body,
            timeout_ms: Some(15000),
        }
    } else {
        // DELETE — cancels the subscription immediately. No body, no Content-Type.
        Request {
            method: Method::Delete,
            url,
            headers: vec![
                ("Authorization".to_string(), format!("Bearer {}", api_key)),
                ("Stripe-Version".to_string(), "2024-12-18".to_string()),
            ],
            body: vec![],
            timeout_ms: Some(15000),
        }
    };

    let response = talos::core::http::fetch(&request)
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
            .map_err(|_| "Failed to parse Stripe API response as JSON".to_string())?;

        talos::core::logging::log(
            Level::Info,
            &format!(
                "stripe-cancel-subscription: subscription {} canceled successfully (at_period_end={})",
                subscription_id, cancel_at_period_end
            ),
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "subscription_id": resp_json.get("id"),
            "status": resp_json.get("status"),
            "cancel_at_period_end": resp_json.get("cancel_at_period_end"),
            "canceled_at": resp_json.get("canceled_at"),
            "current_period_end": resp_json.get("current_period_end"),
            "customer_id": resp_json.get("customer"),
            "livemode": resp_json.get("livemode"),
        }))
        .unwrap())
    } else if response.status == 404 {
        Err(format!("Subscription not found: {}", subscription_id))
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!(
                "stripe-cancel-subscription: API error {}: {}",
                response.status, api_message
            ),
        );
        Err(format!("Stripe API error ({}): {}", response.status, api_message))
    }
}
