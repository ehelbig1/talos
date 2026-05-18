use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));
    
    let selector = config.get("SELECTOR").and_then(|v| v.as_str()).unwrap_or("");
    let transform_type = config.get("TRANSFORM").and_then(|v| v.as_str()).unwrap_or("");
    
    let data = input_json.get("data").unwrap_or(&input_json);
    
    let mut result = data.clone();
    if transform_type == "keys_to_lowercase" {
        // mock
    }
    
    Ok(serde_json::to_string(&result).unwrap_or(input))
}
