use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));
    
    let validation_type = config.get("VALIDATION_TYPE").and_then(|v| v.as_str()).unwrap_or("numeric");
    
    if validation_type == "numeric" {
        if let Some(num) = input_json.get("data").and_then(|v| v.as_f64()) {
            if let Some(min_val) = config.get("MIN_VALUE").and_then(|v| v.as_f64()) {
                if num < min_val {
                    return Err(format!("Validation failed: value {} is less than {}", num, min_val));
                }
            }
            if let Some(max_val) = config.get("MAX_VALUE").and_then(|v| v.as_f64()) {
                if num > max_val {
                    return Err(format!("Validation failed: value {} is greater than {}", num, max_val));
                }
            }
        }
    }
    
    Ok(input)
}
