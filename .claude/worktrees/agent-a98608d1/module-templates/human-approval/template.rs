use talos_sdk_macros::talos_module;

#[talos_module(world = "governance-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));
    
    let reason = config.get("REASON").and_then(|v| v.as_str()).unwrap_or("Approval required");
    
    Ok(format!("Approval requested: {}", reason))
}
