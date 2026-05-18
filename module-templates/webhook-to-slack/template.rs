use talos_sdk_macros::talos_module;

#[talos_module(world = "http-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("Invalid JSON input: {}", e))?;
    let config = input_json
        .get("config")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // ── Extract config ───────────────────────────────────────────────────
    let webhook_url = config
        .get("SLACK_WEBHOOK_URL")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: SLACK_WEBHOOK_URL")?
        .to_string();

    // Validate webhook URL format
    if !webhook_url.starts_with("https://hooks.slack.com/") {
        return Err(format!(
            "SLACK_WEBHOOK_URL must start with 'https://hooks.slack.com/', got: '{}'",
            webhook_url.chars().take(60).collect::<String>()
        ));
    }

    let channel = config
        .get("CHANNEL")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let template = config
        .get("TEMPLATE")
        .and_then(|v| v.as_str())
        .unwrap_or("{{title}}\n{{message}}")
        .to_string();

    let emoji = config
        .get("EMOJI")
        .and_then(|v| v.as_str())
        .unwrap_or(":robot_face:")
        .to_string();

    let username = config
        .get("USERNAME")
        .and_then(|v| v.as_str())
        .unwrap_or("Talos")
        .to_string();

    let use_blocks = config
        .get("USE_BLOCKS")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let color = config
        .get("COLOR")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // ── Extract upstream data ────────────────────────────────────────────
    let data = input_json
        .get("input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // ── Template interpolation ───────────────────────────────────────────
    // Replace {{field}} and {{field.subfield}} with values from the input data.
    fn interpolate(template: &str, ctx: &serde_json::Value) -> String {
        let mut result = template.to_string();
        let mut start = 0;
        let mut iterations = 0;

        loop {
            if iterations > 100 {
                break; // Safety limit
            }
            iterations += 1;

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
                                match cur.get(*part) {
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
                                // Leave unresolved placeholder visible
                                start = close + 2;
                            }
                        }
                    }
                }
            }
        }
        result
    }

    let message_text = interpolate(&template, &data);

    // If template produced empty string, fall back to JSON dump
    let final_text = if message_text.trim().is_empty() {
        match &data {
            serde_json::Value::Null => "Empty input received".to_string(),
            other => serde_json::to_string_pretty(other)
                .unwrap_or_else(|_| other.to_string()),
        }
    } else {
        message_text
    };

    // Truncate very long messages (Slack limit ~40k chars, we cap at 3000 chars for readability).
    //
    // MCP-992 (2026-05-15): char-based truncation, NOT byte slicing.
    // Pre-fix `&final_text[..3000]` was a fixed-byte-offset slice; for
    // any message containing multi-byte UTF-8 codepoints (CJK = 3
    // bytes, emoji = 4 bytes) that crossed byte index 3000, the slice
    // landed mid-codepoint and panicked the WASM module ("byte index
    // 3000 is not a char boundary"). Same family as MCP-477/478/479
    // byte-slice UTF-8 panic class. Use `chars().take(3000)` so the
    // cap is char-count semantically (matching the doc comment) AND
    // can never panic regardless of input.
    let display_text = if final_text.chars().count() > 3000 {
        let truncated: String = final_text.chars().take(3000).collect();
        format!(
            "{}\n... [truncated, {} total characters]",
            truncated,
            final_text.chars().count()
        )
    } else {
        final_text.clone()
    };

    let message_preview: String = display_text.chars().take(100).collect();

    // ── Build Slack payload ──────────────────────────────────────────────
    let payload = if use_blocks {
        // Block Kit format: section block with mrkdwn text + context block
        let mut blocks = vec![
            serde_json::json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": display_text,
                }
            }),
        ];

        // Add a context block with timestamp
        blocks.push(serde_json::json!({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": format!("Sent via {} | {}", username, talos::core::datetime::now_utc()),
                }
            ]
        }));

        let mut payload = serde_json::json!({
            "blocks": blocks,
            "text": display_text, // Fallback for notifications
            "icon_emoji": emoji,
            "username": username,
        });

        if let Some(ref ch) = channel {
            payload["channel"] = serde_json::json!(ch);
        }

        payload
    } else if let Some(ref hex_color) = color {
        // Attachment format with color sidebar
        let mut payload = serde_json::json!({
            "attachments": [{
                "color": hex_color,
                "text": display_text,
                "mrkdwn_in": ["text"],
            }],
            "icon_emoji": emoji,
            "username": username,
        });

        if let Some(ref ch) = channel {
            payload["channel"] = serde_json::json!(ch);
        }

        payload
    } else {
        // Plain text format
        let mut payload = serde_json::json!({
            "text": display_text,
            "icon_emoji": emoji,
            "username": username,
        });

        if let Some(ref ch) = channel {
            payload["channel"] = serde_json::json!(ch);
        }

        payload
    };

    // ── POST to Slack webhook ────────────────────────────────────────────
    use talos::core::http::{Method, Request};

    let body_bytes = serde_json::to_vec(&payload)
        .map_err(|e| format!("Failed to serialize Slack payload: {}", e))?;

    let request = Request {
        method: Method::Post,
        url: webhook_url,
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: body_bytes,
        timeout_ms: Some(10000),
    };

    let resp = talos::core::http::fetch(&request)
        .map_err(|e| format!("Slack webhook request failed: {:?}", e))?;

    let status_code = resp.status;

    if status_code != 200 {
        let body_str = String::from_utf8(resp.body)
            .unwrap_or_else(|_| "<non-utf8>".to_string());
        return Err(format!(
            "Slack webhook error (HTTP {}): {}",
            status_code,
            body_str.chars().take(300).collect::<String>()
        ));
    }

    let result = serde_json::json!({
        "success": true,
        "status_code": status_code,
        "channel": channel,
        "message_preview": message_preview,
    });

    serde_json::to_string(&result).map_err(|e| format!("Failed to serialize output: {}", e))
}
