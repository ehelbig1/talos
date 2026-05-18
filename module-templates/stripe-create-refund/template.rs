use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    use talos::core::http::{Method, Request};
    use talos::core::logging::Level;

    // ── Template interpolation ────────────────────────────────────────────────
    // Replaces {{key}} and {{key.subkey}} in string config values with values
    // from the top-level input_json. Lets CHARGE_ID and PAYMENT_INTENT_ID
    // embed upstream node output: e.g. "{{charge_id}}" where `charge_id` is
    // provided by a webhook trigger node.
    //
    // Rules:
    // - Dot-notation traversal: {{a.b}} → input_json["a"]["b"]
    // - Strings are inlined directly; other types are JSON-serialized.
    // - Unresolved placeholders are left unchanged so misconfiguration is visible.
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
    // Validates Stripe resource IDs before embedding in form parameters.
    // Stripe IDs are alphanumeric with underscores (e.g. ch_xxx, pi_xxx, re_xxx).
    // Whitelist approach rejects path-traversal/injection characters.
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
    // Stripe wraps errors under {"error": {"message": "...", "type": "...", "code": "..."}}.
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

    // ── RFC 3986 percent-encoding ──────────────────────────────────────────────
    // Encodes a string for use in application/x-www-form-urlencoded bodies.
    // Only unreserved characters (A-Z a-z 0-9 - _ . ~) are passed through;
    // all other bytes are percent-encoded as %XX.
    fn url_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
                | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                b => {
                    out.push('%');
                    out.push(char::from_digit((b >> 4) as u32, 16).unwrap().to_ascii_uppercase());
                    out.push(char::from_digit((b & 0xf) as u32, 16).unwrap().to_ascii_uppercase());
                }
            }
        }
        out
    }

    // ── Form body builder ─────────────────────────────────────────────────────
    // Serializes a list of (key, value) pairs into an
    // application/x-www-form-urlencoded byte body.
    fn build_form(params: &[(String, String)]) -> Vec<u8> {
        params
            .iter()
            .enumerate()
            .fold(String::new(), |mut acc, (i, (k, v))| {
                if i > 0 {
                    acc.push('&');
                }
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
        .ok_or("API_KEY_SECRET is required — set it to the vault path holding your Stripe secret key")?;

    // Retrieve the Stripe secret key from the Talos secrets store at runtime.
    // SECURITY: never log the key value — only log its presence.
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Stripe API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "stripe-create-refund: API key retrieved");

    // ── Optional ID fields (interpolated) ────────────────────────────────────
    // Interpolate first, then filter empty strings to None so the mutual-exclusion
    // check below treats an empty (or absent) field the same as a missing one.
    let charge_id: Option<String> = config
        .get("CHARGE_ID")
        .and_then(|v| v.as_str())
        .map(|raw| interpolate(raw, &input_json))
        .filter(|s| !s.is_empty());

    let pi_id: Option<String> = config
        .get("PAYMENT_INTENT_ID")
        .and_then(|v| v.as_str())
        .map(|raw| interpolate(raw, &input_json))
        .filter(|s| !s.is_empty());

    // ── Mutual exclusion validation ────────────────────────────────────────────
    // Exactly one of CHARGE_ID or PAYMENT_INTENT_ID must be supplied.
    let mut params: Vec<(String, String)> = Vec::new();

    match (&charge_id, &pi_id) {
        (Some(c), None) => {
            validate_id(c, "CHARGE_ID")?;
            params.push(("charge".to_string(), c.clone()));
        }
        (None, Some(p)) => {
            validate_id(p, "PAYMENT_INTENT_ID")?;
            params.push(("payment_intent".to_string(), p.clone()));
        }
        (Some(_), Some(_)) => {
            return Err(
                "Provide either CHARGE_ID or PAYMENT_INTENT_ID, not both".to_string(),
            );
        }
        (None, None) => {
            return Err(
                "Either CHARGE_ID or PAYMENT_INTENT_ID is required".to_string(),
            );
        }
    }

    // ── Optional: AMOUNT ──────────────────────────────────────────────────────
    // Accepted as a JSON integer in config; 0 or absent → full refund.
    let amount: u64 = config
        .get("AMOUNT")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if amount > 0 {
        params.push(("amount".to_string(), amount.to_string()));
    }

    // ── Optional: REASON ──────────────────────────────────────────────────────
    // Stripe allowlist: duplicate | fraudulent | requested_by_customer
    if let Some(reason) = config.get("REASON").and_then(|v| v.as_str()) {
        let reason = reason.trim();
        if !reason.is_empty() {
            match reason {
                "duplicate" | "fraudulent" | "requested_by_customer" => {
                    params.push(("reason".to_string(), reason.to_string()));
                }
                _ => {
                    return Err(format!(
                        "REASON must be one of: duplicate, fraudulent, requested_by_customer (got '{}')",
                        reason
                    ));
                }
            }
        }
    }

    // ── Optional: METADATA ────────────────────────────────────────────────────
    // Accepts a JSON object string such as '{"ticket_id": "cs_123"}'.
    // Each top-level key is added as metadata[key]=value in the form body.
    if let Some(metadata_str) = config.get("METADATA").and_then(|v| v.as_str()) {
        let metadata_str = metadata_str.trim();
        if !metadata_str.is_empty() {
            let metadata_obj: serde_json::Value = serde_json::from_str(metadata_str)
                .map_err(|_| "METADATA must be a valid JSON object string (e.g. '{\"ticket_id\": \"cs_123\"}')")?;
            let obj = metadata_obj
                .as_object()
                .ok_or("METADATA must be a JSON object, not an array or scalar")?;
            for (k, v) in obj {
                let val_str = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                params.push((format!("metadata[{}]", k), val_str));
            }
        }
    }

    // ── Audit log ─────────────────────────────────────────────────────────────
    // Log what we are refunding (ID only — never log the API key or amounts at
    // a level that could leak PII, but logging the payment reference is safe
    // and necessary for support audit trails).
    let refund_target = match (&charge_id, &pi_id) {
        (Some(c), _) => format!("charge={}", c),
        (_, Some(p)) => format!("payment_intent={}", p),
        _ => "unknown".to_string(),
    };
    talos::core::logging::log(
        Level::Info,
        &format!("stripe-create-refund: issuing refund ({})", refund_target),
    );

    // ── HTTP request ──────────────────────────────────────────────────────────
    let body_bytes = build_form(&params);

    let request = Request {
        method: Method::Post,
        url: "https://api.stripe.com/v1/refunds".to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Authorization".to_string(), format!("Bearer {}", api_key)),
            ("Stripe-Version".to_string(), "2024-12-18".to_string()),
        ],
        body: body_bytes,
        timeout_ms: Some(15000),
    };

    let response = talos::core::http::fetch(&request)
        .map_err(|e| format!("HTTP request to Stripe failed: {:?}", e))?;

    talos::core::logging::log(
        Level::Info,
        &format!("stripe-create-refund: Stripe API returned HTTP {}", response.status),
    );

    // ── Response handling ─────────────────────────────────────────────────────
    // Cap response size before allocating a String to prevent unbounded memory
    // use from unexpectedly large or malformed Stripe responses.
    const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MB
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Stripe API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body)
        .map_err(|_| "Stripe API response contained invalid UTF-8".to_string())?;

    if response.status == 200 {
        // Stripe refund objects are returned flat at the top level (not nested under "data").
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|e| format!("Failed to parse Stripe refund response: {}", e))?;

        talos::core::logging::log(Level::Info, "stripe-create-refund: refund created successfully");

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "refund_id": resp_json.get("id"),
            "amount": resp_json.get("amount"),
            "currency": resp_json.get("currency"),
            "status": resp_json.get("status"),
            "charge_id": resp_json.get("charge"),
            "payment_intent_id": resp_json.get("payment_intent"),
            "reason": resp_json.get("reason"),
            "created": resp_json.get("created"),
            "livemode": resp_json.get("livemode"),
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!(
                "stripe-create-refund: API error {} for {}: {}",
                response.status, refund_target, api_message
            ),
        );
        Err(format!("Stripe API error ({}): {}", response.status, api_message))
    }
}
