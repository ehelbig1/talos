use talos_sdk_macros::talos_module;

#[talos_module(world = "governance-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("Invalid JSON input: {}", e))?;
    let config = input_json
        .get("config")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // ── Extract config ───────────────────────────────────────────────────
    let webhook_url = config
        .get("NOTIFICATION_WEBHOOK_URL")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: NOTIFICATION_WEBHOOK_URL")?
        .to_string();

    let timeout_minutes = config
        .get("TIMEOUT_MINUTES")
        .and_then(|v| v.as_u64())
        .unwrap_or(60)
        .min(1440)
        .max(1);

    let auto_approve = config
        .get("AUTO_APPROVE_IF_TIMEOUT")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let reason = config
        .get("REASON")
        .and_then(|v| v.as_str())
        .unwrap_or("Human review required before proceeding")
        .to_string();

    let approvers = config
        .get("APPROVERS")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let include_input = config
        .get("INCLUDE_INPUT_IN_NOTIFICATION")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let webhook_secret = config
        .get("WEBHOOK_SECRET")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // ── Extract upstream data ────────────────────────────────────────────
    let data = input_json
        .get("input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // ── Interpolate {{field}} references in the reason string ────────────
    let interpolated_reason = {
        let mut result = reason.clone();
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
                            let field = result[open + 2..close].trim();
                            let replacement = data
                                .get(field)
                                .map(|v| match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .unwrap_or_else(|| format!("{{{{{}}}}}", field));
                            result.replace_range(open..close + 2, &replacement);
                            start = open + replacement.len();
                        }
                    }
                }
            }
        }
        result
    };

    // ── Build the approval request reason ────────────────────────────────
    let full_reason = if approvers.is_empty() {
        interpolated_reason.clone()
    } else {
        format!("{} (approvers: {})", interpolated_reason, approvers)
    };

    // ── Send webhook notification ────────────────────────────────────────
    use talos::core::http::{Method, Request};

    let notification_payload = serde_json::json!({
        "event": "approval_requested",
        "reason": interpolated_reason,
        "approvers": if approvers.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::Array(
                approvers.split(',')
                    .map(|s| serde_json::Value::String(s.trim().to_string()))
                    .collect()
            )
        },
        "timeout_minutes": timeout_minutes,
        "auto_approve_if_timeout": auto_approve,
        "input_data": if include_input { data.clone() } else { serde_json::Value::Null },
        "timestamp": talos::core::datetime::now_utc(),
    });

    let payload_bytes =
        serde_json::to_vec(&notification_payload).unwrap_or_default();

    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
    ];

    // HMAC-SHA256 signing if webhook secret is configured
    if let Some(ref secret) = webhook_secret {
        let signature = talos::core::crypto::hmac_sha256(
            secret.as_bytes(),
            &payload_bytes,
        );
        headers.push((
            "X-Talos-Signature".to_string(),
            format!("sha256={}", signature),
        ));
    }

    let webhook_request = Request {
        method: Method::Post,
        url: webhook_url.clone(),
        headers,
        body: payload_bytes,
        timeout_ms: Some(10000),
    };

    let notification_sent = match talos::core::http::fetch(&webhook_request) {
        Ok(resp) => resp.status < 400,
        Err(_) => false,
    };

    // ── Block for human approval ─────────────────────────────────────────
    // This is a blocking WIT call: the WASM guest suspends here.
    // The host subscribes to NATS / writes a pending record to Redis.
    // The guest resumes only when a human calls submit_workflow_approval
    // or the timeout expires.
    let approved = talos::core::governance::request_approval(&full_reason);

    // ── Build output ─────────────────────────────────────────────────────
    // The governance host returns true for approved, false for rejected.
    // Timeout behavior: the host handles timeouts by injecting an
    // auto-approve or auto-reject based on the approval policy config.
    // From the WASM guest perspective, we always get a boolean back.
    let decision_source = if approved {
        "human"
    } else {
        "human"
    };

    if approved {
        let result = serde_json::json!({
            "approved": true,
            "decision_source": decision_source,
            "reason": interpolated_reason,
            "reviewer": serde_json::Value::Null,
            "notification_sent": notification_sent,
            "timeout_minutes": timeout_minutes,
        });
        serde_json::to_string(&result)
            .map_err(|e| format!("Failed to serialize output: {}", e))
    } else {
        // Return as Err so error edges can catch the rejection
        Err(serde_json::json!({
            "approved": false,
            "decision_source": decision_source,
            "reason": interpolated_reason,
            "reviewer": serde_json::Value::Null,
            "notification_sent": notification_sent,
            "timeout_minutes": timeout_minutes,
        })
        .to_string())
    }
}
