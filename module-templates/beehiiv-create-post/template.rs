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

    // ── API error extraction ──────────────────────────────────────────────────
    fn extract_api_error(body: &str, status: u16) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|j| j.get("message").and_then(|m| m.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| format!("HTTP {}", status))
    }

    // ── Comma-separated list parser ───────────────────────────────────────────
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

    let title_raw = config
        .get("TITLE")
        .and_then(|v| v.as_str())
        .ok_or("TITLE is required")?;
    let title = interpolate(title_raw, &input_json);
    if title.is_empty() {
        return Err("TITLE must not be empty".to_string());
    }
    // Count once — chars().count() is O(n) on UTF-8 strings
    let title_char_count = title.chars().count();
    if title_char_count > 250 {
        return Err(format!(
            "TITLE exceeds 250 characters ({} chars) — truncate before passing to this node",
            title_char_count
        ));
    }

    // ── Status validation ─────────────────────────────────────────────────────
    let status = config
        .get("STATUS")
        .and_then(|v| v.as_str())
        .unwrap_or("draft");
    if status != "draft" && status != "confirmed" {
        return Err(format!("STATUS must be 'draft' or 'confirmed', got '{}'", status));
    }

    // ── Retrieve API key from secret vault ────────────────────────────────────
    let api_key = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve Beehiiv API key from '{}': {:?}", api_key_secret, e))?;

    talos::core::logging::log(Level::Info, "beehiiv-create-post: API key retrieved");

    // ── Build request body ────────────────────────────────────────────────────
    let mut body = serde_json::json!({
        "title": title,
        "status": status,
    });

    // Subtitle
    if let Some(raw) = config.get("SUBTITLE").and_then(|v| v.as_str()) {
        let val = interpolate(raw, &input_json);
        if !val.is_empty() {
            body["subtitle"] = serde_json::json!(val);
        }
    }

    // Body content (HTML) — enforce a size cap to prevent oversized payloads
    if let Some(raw) = config.get("BODY_CONTENT").and_then(|v| v.as_str()) {
        let val = interpolate(raw, &input_json);
        if !val.is_empty() {
            // 1 MB cap — Beehiiv's limit is not publicly documented but this is conservative
            const MAX_BODY_BYTES: usize = 1_048_576;
            if val.len() > MAX_BODY_BYTES {
                return Err(format!(
                    "BODY_CONTENT exceeds 1 MB ({} bytes) — split content or summarize before passing to this node",
                    val.len()
                ));
            }
            body["body_content"] = serde_json::json!(val);
        }
    }

    // Scheduled delivery time (only relevant when status=confirmed)
    if let Some(raw) = config.get("SCHEDULED_AT").and_then(|v| v.as_str()) {
        let val = interpolate(raw, &input_json);
        if !val.is_empty() {
            // Basic ISO 8601 sanity check — must contain 'T' date/time separator
            if !val.contains('T') {
                return Err(format!(
                    "SCHEDULED_AT must be ISO 8601 (e.g. '2026-06-01T09:00:00Z'), got '{}'",
                    val
                ));
            }
            body["scheduled_at"] = serde_json::json!(val);
        }
    }

    // Thumbnail image URL
    if let Some(raw) = config.get("THUMBNAIL_IMAGE_URL").and_then(|v| v.as_str()) {
        let val = interpolate(raw, &input_json);
        if !val.is_empty() {
            if !val.starts_with("https://") && !val.starts_with("http://") {
                return Err("THUMBNAIL_IMAGE_URL must start with http:// or https://".to_string());
            }
            body["thumbnail_image_url"] = serde_json::json!(val);
        }
    }

    // Content tags (comma-separated → array)
    if let Some(tags_str) = config.get("CONTENT_TAGS").and_then(|v| v.as_str()) {
        if let Some(tags) = parse_comma_list(tags_str) {
            body["content_tags"] = tags;
        }
    }

    // Email settings: build object only if at least one field is configured
    let email_subject = config.get("EMAIL_SUBJECT").and_then(|v| v.as_str())
        .map(|r| interpolate(r, &input_json))
        .filter(|s| !s.is_empty());
    let email_preview = config.get("EMAIL_PREVIEW_TEXT").and_then(|v| v.as_str())
        .map(|r| interpolate(r, &input_json))
        .filter(|s| !s.is_empty());

    if email_subject.is_some() || email_preview.is_some() {
        let mut email_settings = serde_json::json!({});
        if let Some(subj) = email_subject {
            email_settings["subject_line"] = serde_json::json!(subj);
        }
        if let Some(preview) = email_preview {
            email_settings["preview_text"] = serde_json::json!(preview);
        }
        body["email_settings"] = email_settings;
    }

    // ── HTTP request ──────────────────────────────────────────────────────────
    let url = format!(
        "https://api.beehiiv.com/v2/publications/{}/posts",
        publication_id
    );

    talos::core::logging::log(
        Level::Info,
        &format!(
            "beehiiv-create-post: creating post with status='{}' in publication {}",
            status, publication_id
        ),
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
        timeout_ms: Some(30000),
    })
    .map_err(|e| format!("HTTP request to Beehiiv failed: {:?}", e))?;

    // ── Response handling ─────────────────────────────────────────────────────
    const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MB
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err("Beehiiv API response body exceeds 1 MB size limit".to_string());
    }
    let body_str = String::from_utf8(response.body).unwrap_or_default();

    if response.status == 201 || response.status == 200 {
        let resp_json: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|_| "Failed to parse Beehiiv API response".to_string())?;

        let data = resp_json.get("data").unwrap_or(&resp_json);

        talos::core::logging::log(
            Level::Info,
            &format!(
                "beehiiv-create-post: post created successfully with status='{}'",
                status
            ),
        );

        Ok(serde_json::to_string(&serde_json::json!({
            "success": true,
            "post_id": data.get("id"),
            "title": data.get("title"),
            "status": data.get("status"),
            "web_url": data.get("web_url"),
            "thumbnail_url": data.get("thumbnail_url"),
            "created": data.get("created"),
            "content_tags": data.get("content_tags"),
        }))
        .unwrap())
    } else {
        let api_message = extract_api_error(&body_str, response.status);
        talos::core::logging::log(
            Level::Error,
            &format!("beehiiv-create-post: API error {}: {}", response.status, api_message),
        );
        Err(format!("Beehiiv API error ({}): {}", response.status, api_message))
    }
}
