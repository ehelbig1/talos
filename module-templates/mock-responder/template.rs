use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    // FAIL_WITH: simulate an error path for testing
    if let Some(err) = config.get("FAIL_WITH").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        return Err(err.to_string());
    }

    let response_str = config.get("RESPONSE").and_then(|v| v.as_str())
        .ok_or("Missing required config: RESPONSE")?;

    // Parse to validate JSON, then re-serialize to normalize
    let mut response: serde_json::Value = serde_json::from_str(response_str)
        .map_err(|e| format!("RESPONSE must be valid JSON: {}", e))?;

    // ECHO_INPUT: attach original input under __input__
    if config.get("ECHO_INPUT").and_then(|v| v.as_bool()).unwrap_or(false) {
        if let Some(obj) = response.as_object_mut() {
            obj.insert("__input__".to_string(), input_json);
        }
    }

    Ok(response.to_string())
}
