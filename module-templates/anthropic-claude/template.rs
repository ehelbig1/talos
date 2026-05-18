use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    let api_key_secret = config.get("API_KEY_SECRET").and_then(|v| v.as_str())
        .ok_or("Missing required config: API_KEY_SECRET")?;
    let output_schema_str = config.get("OUTPUT_SCHEMA").and_then(|v| v.as_str())
        .ok_or("Missing required config: OUTPUT_SCHEMA — this template always uses tool_use structured output")?;
    let model = config.get("MODEL").and_then(|v| v.as_str()).unwrap_or("claude-sonnet-4-6");
    let max_tokens = config.get("MAX_TOKENS").and_then(|v| v.as_u64()).unwrap_or(1024);
    let system_prompt = config.get("SYSTEM_PROMPT").and_then(|v| v.as_str())
        .unwrap_or("You are a helpful assistant.");

    let output_schema: serde_json::Value = serde_json::from_str(output_schema_str)
        .map_err(|e| format!("OUTPUT_SCHEMA must be a valid JSON Schema object: {}", e))?;

    // Resolve API key to a host-side slot handle (Tier 1).
    // The key value never crosses into guest memory.
    let api_key_slot = talos::core::secrets::get_secret(api_key_secret)
        .map_err(|e| format!("Failed to retrieve API key '{}': {:?}", api_key_secret, e))?;

    // Build the user message content from the input
    let user_message = input_json.get("input")
        .map(|v| v.to_string())
        .unwrap_or_else(|| input_json.to_string());

    // Always use tool_use for structured output
    let body = serde_json::json!({
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{ "role": "user", "content": user_message }],
        "tools": [{
            "name": "structured_output",
            "description": "Return structured data according to the specified schema",
            "input_schema": output_schema
        }],
        "tool_choice": { "type": "tool", "name": "structured_output" }
    });

    use talos::core::http::{Request, Method};

    // Tier 1: x-api-key is injected by the host via fetch_with_header.
    // The key value never crosses into guest memory.
    let request = Request {
        method: Method::Post,
        url: "https://api.anthropic.com/v1/messages".to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("anthropic-version".to_string(), "2023-06-01".to_string()),
        ],
        body: serde_json::to_vec(&body).unwrap(),
        timeout_ms: Some(30000),
    };

    match talos::core::http::fetch_with_header(api_key_slot, "x-api-key", &request) {
        Ok(resp) => {
            let body_str = String::from_utf8(resp.body)
                .map_err(|_| "Invalid UTF-8 in Anthropic response".to_string())?;
            if body_str.len() > 1_048_576 {
                return Err("Anthropic response exceeds 1MB safety limit".to_string());
            }

            if resp.status == 401 || resp.status == 403 {
                return Err(format!(
                    "Anthropic API authentication error (HTTP {}): {} — check API_KEY_SECRET.",
                    resp.status, body_str.chars().take(500).collect::<String>()
                ));
            }
            if resp.status == 429 {
                return Err(format!(
                    "Anthropic API rate limit exceeded (HTTP 429): {}",
                    body_str.chars().take(300).collect::<String>()
                ));
            }
            if resp.status >= 400 {
                return Err(format!(
                    "Anthropic API error (HTTP {}): {}",
                    resp.status, body_str.chars().take(500).collect::<String>()
                ));
            }

            let response: serde_json::Value = serde_json::from_str(&body_str)
                .map_err(|e| format!("Invalid JSON from Anthropic API: {}", e))?;

            // Extract structured output from tool_use response: content[0].input
            let tool_input = response
                .get("content")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("input"));

            match tool_input {
                Some(input) => serde_json::to_string(input)
                    .map_err(|e| format!("Failed to serialize tool_use output: {}", e)),
                None => {
                    // Diagnose specific failure modes for actionable errors
                    let stop_reason = response.get("stop_reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let content = response.get("content")
                        .and_then(|c| c.as_array());
                    let content_count = content.map(|c| c.len()).unwrap_or(0);

                    let error_detail = if stop_reason == "max_tokens" {
                        "LLM response truncated — increase MAX_TOKENS"
                    } else if stop_reason == "end_turn" && content_count > 0 {
                        "LLM did not use the output tool — check OUTPUT_SCHEMA"
                    } else if content_count == 0 {
                        "LLM returned empty response"
                    } else {
                        "tool_use extraction failed — see raw_preview"
                    };

                    let raw_preview: String = body_str.chars().take(500).collect();

                    let error_output = serde_json::json!({
                        "__error": true,
                        "error_type": "tool_use_extraction_failed",
                        "error_detail": error_detail,
                        "stop_reason": stop_reason,
                        "content_blocks": content_count,
                        "raw_preview": raw_preview,
                    });
                    serde_json::to_string(&error_output)
                        .map_err(|e| e.to_string())
                }
            }
        }
        Err(_) => Err(
            "HTTP request to Anthropic API failed — check API_KEY_SECRET and host allowlist".to_string()
        ),
    }
}
