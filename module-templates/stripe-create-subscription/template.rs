use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    use talos::core::http::{Method, Request};
    use talos::core::logging::Level;

    // ── Template interpolation ────────────────────────────────────────────────
    // Replaces {{key}} and {{key.subkey}} patterns in string config values with
    // values from the top-level input_json. Dot-notation traversal is supported.
    // If the path is not found the placeholder is left unchanged so
    // misconfigured templates are visible rather than silently swallowed.
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
    // Rejects values that contain characters unsafe for use as Stripe IDs.
    // Stripe IDs are alphanumeric with underscores and hyphens only.
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

    // ── Stripe error extraction ───────────────────────────────────────────────
    // Stripe error bodies have shape: {"error": {"message": "...", "type": "...", "code": "..."}}
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

    // ── RFC 3986 percent-encoding ─────────────────────────────────────────────
    // Encodes all characters except unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
    // Required for application/x-www-form-urlencoded bodies sent to Stripe.
    fn url_encode(s: &str) -> String {
        let mut encoded = String::with_capacity(s.len());
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~' => encoded.push(byte as char),
                b => {
                    encoded.push('%');
                    encoded.push(char::from_digit((b >> 4) as u32, 16).unwrap().to_ascii_uppercase());
                    encoded.push(char::from_digit((b & 0xf) as u32, 16).unwrap().to_ascii_uppercase());
                }
            }
        }
        encoded
    }

    // ── Form body builder ─────────────────────────────────────────────────────
    // Joins key=value pairs with "&". Both keys and values must already be
    // url_encode'd or be safe ASCII (param names we control are all safe).
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

    // ── Retrieve API key ──────────────────────────────────────────────────────
    let api_key_secret = config
        .get("API_KEY_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("API_KEY_SECRET is required")?;
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Stripe secret key from '{}': {}", api_key_secret, e))?;

    // ── CUSTOMER_ID ───────────────────────────────────────────────────────────
    let customer_id_raw = config
        .get("CUSTOMER_ID")
        .and_then(|v| v.as_str())
        .ok_or("CUSTOMER_ID is required")?;
    let customer_id = interpolate(customer_id_raw, &input_json);
    validate_id(&customer_id, "CUSTOMER_ID")?;

    // ── PRICE_ID ──────────────────────────────────────────────────────────────
    let price_id_raw = config
        .get("PRICE_ID")
        .and_then(|v| v.as_str())
        .ok_or("PRICE_ID is required")?;
    let price_id = interpolate(price_id_raw, &input_json);
    validate_id(&price_id, "PRICE_ID")?;

    // ── QUANTITY ──────────────────────────────────────────────────────────────
    let quantity: u64 = config
        .get("QUANTITY")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    if quantity < 1 {
        return Err("QUANTITY must be at least 1".to_string());
    }

    // ── PAYMENT_BEHAVIOR ──────────────────────────────────────────────────────
    let allowed_behaviors = ["default_incomplete", "error_if_incomplete", "allow_incomplete"];
    let payment_behavior = config
        .get("PAYMENT_BEHAVIOR")
        .and_then(|v| v.as_str())
        .unwrap_or("default_incomplete");
    if !allowed_behaviors.contains(&payment_behavior) {
        return Err(format!(
            "PAYMENT_BEHAVIOR '{}' is not valid — must be one of: {}",
            payment_behavior,
            allowed_behaviors.join(", ")
        ));
    }

    // ── CANCEL_AT_PERIOD_END ──────────────────────────────────────────────────
    let cancel_at_period_end: bool = config
        .get("CANCEL_AT_PERIOD_END")
        .map(|v| {
            v.as_bool()
                .unwrap_or_else(|| v.as_str().map(|s| s.eq_ignore_ascii_case("true")).unwrap_or(false))
        })
        .unwrap_or(false);

    // ── TRIAL_END (takes priority over TRIAL_PERIOD_DAYS if both set) ─────────
    let trial_end_raw = config
        .get("TRIAL_END")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| interpolate(s, &input_json));
    let trial_end_ts: Option<u64> = if let Some(ref ts_str) = trial_end_raw {
        let parsed = ts_str
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("TRIAL_END '{}' is not a valid unix timestamp (must be a positive integer)", ts_str))?;
        Some(parsed)
    } else {
        None
    };

    let trial_period_days: Option<u64> = if trial_end_ts.is_none() {
        config.get("TRIAL_PERIOD_DAYS").and_then(|v| v.as_u64())
    } else {
        None // TRIAL_END wins; ignore TRIAL_PERIOD_DAYS
    };

    // ── METADATA ──────────────────────────────────────────────────────────────
    // Accepts a JSON object string e.g. '{"plan_name": "pro", "user_id": "u_123"}'.
    // Keys: max 40 chars. Values: max 500 chars. Max 50 entries (Stripe limit).
    let metadata_pairs: Vec<(String, String)> = if let Some(meta_str) = config
        .get("METADATA")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        let meta_val: serde_json::Value = serde_json::from_str(meta_str)
            .map_err(|e| format!("METADATA is not valid JSON: {}", e))?;
        let obj = meta_val
            .as_object()
            .ok_or("METADATA must be a JSON object (e.g. '{\"key\": \"value\"}')")?;
        if obj.len() > 50 {
            return Err(format!(
                "METADATA has {} entries — Stripe allows a maximum of 50 metadata keys",
                obj.len()
            ));
        }
        let mut pairs = Vec::with_capacity(obj.len());
        for (k, v) in obj {
            if k.len() > 40 {
                return Err(format!(
                    "METADATA key '{}' exceeds 40 characters (Stripe limit)",
                    k.chars().take(45).collect::<String>()
                ));
            }
            let val_string = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "null".to_string(),
                other => other.to_string(),
            };
            if val_string.len() > 500 {
                return Err(format!(
                    "METADATA value for key '{}' exceeds 500 characters (Stripe limit)",
                    k
                ));
            }
            pairs.push((format!("metadata[{}]", k), val_string));
        }
        pairs
    } else {
        vec![]
    };

    // ── Build form params ─────────────────────────────────────────────────────
    // Order: required fields first, then optional, then metadata.
    let mut params: Vec<(String, String)> = vec![
        ("customer".to_string(), customer_id.clone()),
        ("items[0][price]".to_string(), price_id.clone()),
        ("items[0][quantity]".to_string(), quantity.to_string()),
        ("payment_behavior".to_string(), payment_behavior.to_string()),
        (
            "cancel_at_period_end".to_string(),
            cancel_at_period_end.to_string(),
        ),
    ];

    // Expand latest_invoice.payment_intent so we can pull out client_secret for 3DS.
    params.push(("expand[0]".to_string(), "latest_invoice.payment_intent".to_string()));

    if let Some(ts) = trial_end_ts {
        params.push(("trial_end".to_string(), ts.to_string()));
    } else if let Some(days) = trial_period_days {
        params.push(("trial_period_days".to_string(), days.to_string()));
    }

    for (k, v) in metadata_pairs {
        params.push((k, v));
    }

    let form_body = build_form(&params);

    // ── HTTP request ──────────────────────────────────────────────────────────
    let request = Request {
        method: Method::Post,
        url: "https://api.stripe.com/v1/subscriptions".to_string(),
        headers: vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Authorization".to_string(), format!("Bearer {}", api_key)),
            ("Stripe-Version".to_string(), "2024-12-18".to_string()),
        ],
        body: form_body,
        timeout_ms: Some(20000),
    };

    match talos::core::http::fetch(&request) {
        Ok(resp) => {
            // ── Safety cap ────────────────────────────────────────────────────
            const MAX_RESPONSE_BYTES: usize = 1_048_576;
            if resp.body.len() > MAX_RESPONSE_BYTES {
                return Err(format!(
                    "Stripe response body exceeds {} bytes safety limit — aborting",
                    MAX_RESPONSE_BYTES
                ));
            }

            let body_str = String::from_utf8(resp.body)
                .map_err(|_| "Stripe response contains invalid UTF-8".to_string())?;

            // ── Error handling ────────────────────────────────────────────────
            if resp.status == 401 || resp.status == 403 {
                return Err(format!(
                    "Stripe API authentication error (HTTP {}): {} — check the credential at '{}' (API_KEY_SECRET config key).",
                    resp.status,
                    extract_api_error(&body_str, resp.status),
                    api_key_secret
                ));
            }
            if resp.status == 402 {
                return Err(format!(
                    "Stripe payment required (HTTP 402): {} — the customer's payment method may be declined or missing.",
                    extract_api_error(&body_str, resp.status)
                ));
            }
            if resp.status == 429 {
                return Err(format!(
                    "Stripe API rate limit exceeded (HTTP 429): {} — retry after a delay or reduce request frequency.",
                    extract_api_error(&body_str, resp.status)
                ));
            }
            if resp.status >= 400 {
                return Err(format!(
                    "Stripe API error (HTTP {}): {}",
                    resp.status,
                    extract_api_error(&body_str, resp.status)
                ));
            }

            // ── Parse successful response ─────────────────────────────────────
            // Stripe subscription responses are JSON at the top level (not nested under "data").
            let resp_json: serde_json::Value = serde_json::from_str(&body_str)
                .map_err(|e| format!("Failed to parse Stripe subscription response as JSON: {}", e))?;

            // ── Extract client_secret for 3DS flows ───────────────────────────
            // Path: resp_json["latest_invoice"]["payment_intent"]["client_secret"]
            // The "expand" param above ensures payment_intent is an object, not just an ID.
            let client_secret = resp_json
                .get("latest_invoice")
                .and_then(|inv| inv.get("payment_intent"))
                .and_then(|pi| pi.get("client_secret"));

            Ok(serde_json::to_string(&serde_json::json!({
                "success": true,
                "subscription_id": resp_json.get("id"),
                "status": resp_json.get("status"),
                "customer_id": resp_json.get("customer"),
                "current_period_start": resp_json.get("current_period_start"),
                "current_period_end": resp_json.get("current_period_end"),
                "trial_start": resp_json.get("trial_start"),
                "trial_end": resp_json.get("trial_end"),
                "cancel_at_period_end": resp_json.get("cancel_at_period_end"),
                "livemode": resp_json.get("livemode"),
                "client_secret": client_secret,
            })).unwrap())
        }
        Err(e) => Err(format!(
            "Network error reaching Stripe API: {} — verify that api.stripe.com is in the node's allowed_hosts list.",
            e
        )),
    }
}
