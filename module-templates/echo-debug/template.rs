use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));
    
    let prefix = config.get("PREFIX").and_then(|v| v.as_str()).unwrap_or("");
    let uppercase = config.get("UPPERCASE").and_then(|v| v.as_bool()).unwrap_or(false);
    let log_to_console = config.get("LOG_TO_CONSOLE").and_then(|v| v.as_bool()).unwrap_or(true);
    
    let mut output = format!("{}{}", prefix, input);
    
    if uppercase {
        output = output.to_uppercase();
    }
    
    if log_to_console {
        // Log to console using the SDK
        use talos::core::logging::{self, Level};
        
        let payload_to_log = if let Some(input_val) = input_json.get("input") {
            input_val.to_string()
        } else {
            input.clone()
        };
        
        logging::log(Level::Info, &format!("Echo Input Payload: {}", payload_to_log));
        
        let output_to_log = if uppercase {
            output.to_uppercase()
        } else {
            output.clone()
        };
        
        logging::log(Level::Info, &format!("Echo Output Result: {}", output_to_log));
    }
    
    Ok(output)
}
