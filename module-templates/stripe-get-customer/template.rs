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

    // ── API error extraction (Stripe error envelope) ──────────────────────────
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

    // ── Required config ───────────────────────────────────────────────────────
    let api_key_secret = config
        .get("API_KEY_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("API_KEY_SECRET is required")?;

    let customer_id_raw = config
        .get("CUSTOMER_ID")
        .and_then(|v| v.as_str())
        .ok_or("CUSTOMER_ID is required")?;
    let customer_id = interpolate(customer_id_raw, &input_json);
    validate_id(&customer_id, "CUSTOMER_ID")?;

    // ── Optional config ───────────────────────────────────────────────────────
    let expand_subscriptions = config
        .get("EXPAND_SUBSCRIPTIONS")
        .map(|v| {
            v.as_bool().unwrap_or_else(|| {
                v.as_str()
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    // ── Retrieve API key from secret vault ────────────────────────────────────
    // SECURITY: never log the key value — presence only.
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Stripe API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "stripe-get-customer: API key retrieved");

    // ── URL construction ──────────────────────────────────────────────────────
    // Brackets in query param names must be percent-encoded for correct Stripe parsing.
    // expand%5B%5D=subscriptions → expand[]=subscriptions
    let url = if expand_subscriptions {
        format!(
            "https://api.stripe.com/v1/customers/{}?expand%5B%5D=subscriptions",
            customer_id
        )
    } else {
        format!("https://api.stripe.com/v1/customers/{}", customer_id)
    };

    talos::core::logging::log(
        Level::Info,
        &format!(
            "stripe-get-customer: fetching customer {} (expand_subscriptions={})",
            customer_id, expand_subscriptions
        ),
    );

    // ── HTTP GET request ──────────────────────────────────────────────────────
    // GET requests carry no body and no Content-Type header.
    let response = talos::core::http::fetch(&Request {
        method: Method::Get,
        url,
        headers: vec![
            ("Authorization".to_string(), format!("Bearer {}", api_key)),
            ("Stripe-Version".to_string(), "2024-12-18".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(10000),
    })
    .map_err(|e| format!("HTTP request to Stripe failed: {:?}", e))?;

    // ── Response handling ─────────────────────────────────────────────────────
    const MAX_RESPONSE_BYTES: usize = 1_048_576;
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Stripe API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body)
        .map_err(|_| "Invalid UTF-8 in Stripe API response".to_string())?;

    if response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Stripe API response".to_string())?;

        // Extract subscription convenience fields for condition branching.
        // Stripe always includes `subscriptions` as a paginated list object even when
        // not expanded — use total_count for a reliable presence check.
        let subscription_count = resp_json
            .get("subscriptions")
            .and_then(|s| s.get("total_count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let has_subscriptions = subscription_count > 0;

        talos::core::logging::log(
            Level::Info,
            &format!(
                "stripe-get-customer: customer {} retrieved (subscriptions: {})",
                customer_id, subscription_count
            ),
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            // Core identity fields
            "customer_id":   resp_json.get("id"),
            "email":         resp_json.get("email"),
            "name":          resp_json.get("name"),
            "phone":         resp_json.get("phone"),
            "description":   resp_json.get("description"),
            // Billing fields
            "balance":       resp_json.get("balance"),
            "currency":      resp_json.get("currency"),
            "delinquent":    resp_json.get("delinquent"),
            // Metadata
            "created":       resp_json.get("created"),
            "livemode":      resp_json.get("livemode"),
            "metadata":      resp_json.get("metadata"),
            // Subscriptions — present as paginated list object regardless of expansion.
            // When EXPAND_SUBSCRIPTIONS=true the `data` array is populated with full objects.
            "subscriptions":       resp_json.get("subscriptions"),
            // Convenience fields for condition branching
            "subscription_count":  subscription_count,
            "has_subscriptions":   has_subscriptions,
        }))
        .unwrap())
    } else if response.status == 404 {
        Err(format!("Customer not found: {}", customer_id))
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!(
                "stripe-get-customer: API error {}: {}",
                response.status, api_message
            ),
        );
        Err(format!("Stripe API error ({}): {}", response.status, api_message))
    }
}
