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

    // ── Optional referral count for milestone comparison ───────────────────────
    // Accepts either a numeric config value or a string template like
    // {{stats.referrals_count}} resolved from an upstream beehiiv-get-subscriber node.
    // Single lookup: try string-interpolation path first, fall back to direct u64.
    let referral_count: Option<u64> = config.get("REFERRAL_COUNT").and_then(|v| {
        v.as_str()
            .map(|s| interpolate(s, &input_json))
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| v.as_u64())
    });

    // ── Retrieve API key from secret vault ────────────────────────────────────
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-get-referral-program: API key retrieved");

    // ── HTTP request ──────────────────────────────────────────────────────────
    let url = format!(
        "https://api.beehiiv.com/v2/publications/{}/referral_program",
        publication_id
    );

    talos::core::logging::log(
        Level::Info,
        &format!("beehiiv-get-referral-program: fetching referral program for publication {}", publication_id),
    );

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
    const MAX_RESPONSE_BYTES: usize = 1_048_576;
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Beehiiv API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body).unwrap_or_default();

    if response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Beehiiv API response".to_string())?;

        // The API returns { "data": { "milestones": [...], "enabled": bool, ... } }
        let data = resp_json.get("data").unwrap_or(&resp_json);
        let enabled = data.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);

        // Keep a reference for the output; derive the slice from it — no clone needed.
        let milestones_ref = data.get("milestones");
        let milestones_arr = milestones_ref
            .and_then(|m| m.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        let milestone_count = milestones_arr.len();

        talos::core::logging::log(
            Level::Info,
            &format!(
                "beehiiv-get-referral-program: publication {} has {} milestones, enabled={}",
                publication_id, milestone_count, enabled
            ),
        );

        // ── Milestone comparison (only when REFERRAL_COUNT is provided) ─────────
        // crossed_milestones: all milestones the subscriber has reached (num_referrals <= count)
        // next_milestone: the lowest milestone above the subscriber's current count
        // Single pass over the array via fold — avoids double iteration.
        let (crossed_milestones, next_milestone) = if let Some(count) = referral_count {
            let (crossed_vec, next_val) = milestones_arr.iter().fold(
                (Vec::new(), None::<serde_json::Value>),
                |(mut crossed, mut next_min), m| {
                    if let Some(threshold) = m.get("num_referrals").and_then(|v| v.as_u64()) {
                        if threshold <= count {
                            crossed.push(m.clone());
                        } else {
                            // Keep whichever uncrossed milestone has the smallest threshold
                            let is_closer = next_min
                                .as_ref()
                                .and_then(|n| n.get("num_referrals").and_then(|v| v.as_u64()))
                                .map(|cur| threshold < cur)
                                .unwrap_or(true);
                            if is_closer {
                                next_min = Some(m.clone());
                            }
                        }
                    }
                    (crossed, next_min)
                },
            );

            talos::core::logging::log(
                Level::Info,
                &format!(
                    "beehiiv-get-referral-program: referral_count={}, crossed={}, has_next={}",
                    count,
                    crossed_vec.len(),
                    next_val.is_some()
                ),
            );

            (
                serde_json::json!(crossed_vec),
                next_val.unwrap_or(serde_json::json!(null)),
            )
        } else {
            (serde_json::json!(null), serde_json::json!(null))
        };

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "referral_program_enabled": enabled,
            "milestones": milestones_ref,  // Option<&Value>: null if key absent
            "milestone_count": milestone_count,
            // Only populated when REFERRAL_COUNT is configured
            "crossed_milestones": crossed_milestones,
            "next_milestone": next_milestone,
        }))
        .unwrap())
    } else if response.status == 404 {
        Err(format!("Publication not found or referral program not configured: {}", publication_id))
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-get-referral-program: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
