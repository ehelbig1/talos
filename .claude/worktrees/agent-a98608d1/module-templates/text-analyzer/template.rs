use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};

    // 1. Parse the input JSON payload
    let input_json: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    // 2. Extract configuration
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));
    
    // 3. Get the text to analyze
    let text_to_analyze = input_json.get("text")
        .and_then(|v| v.as_str())
        .or_else(|| config.get("DEFAULT_TEXT").and_then(|v| v.as_str()))
        .unwrap_or("");

    logging::log(Level::Info, &format!("Analyzing text of length: {}", text_to_analyze.len()));

    // 4. Perform business logic
    let char_count = text_to_analyze.chars().count();
    let word_count = text_to_analyze.split_whitespace().count();
    let line_count = text_to_analyze.lines().count();

    // 5. Construct the output
    let output = serde_json::json!({
        "success": true,
        "metrics": {
            "characters": char_count,
            "words": word_count,
            "lines": line_count,
        },
        "original_text_preview": text_to_analyze.chars().take(50).collect::<String>()
    });

    serde_json::to_string(&output).map_err(|e| format!("Failed to serialize: {}", e))
}
