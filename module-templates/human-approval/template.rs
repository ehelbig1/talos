use talos_sdk_macros::talos_module;

#[talos_module(world = "governance-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    let reason = config
        .get("REASON")
        .and_then(|v| v.as_str())
        .unwrap_or("Manual review required")
        .to_string();

    let approvers = config
        .get("APPROVERS")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Build the approval request message shown to the approver.
    let request_reason = if approvers.is_empty() {
        reason.clone()
    } else {
        format!("{} (approvers: {})", reason, approvers)
    };

    // Blocking call — execution pauses here until a human approves or rejects
    // via the workflow approval API.  The host subscribes to NATS and writes a
    // pending record to Redis; this WASM guest resumes only when the reply arrives.
    let approved = talos::core::governance::request_approval(&request_reason);

    if approved {
        Ok(serde_json::json!({
            "approved": true,
            "reason": reason,
            "status": "approved"
        })
        .to_string())
    } else {
        Err(serde_json::json!({
            "approved": false,
            "reason": reason,
            "status": "rejected"
        })
        .to_string())
    }
}
