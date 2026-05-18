use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
        let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
        let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

        use talos::core::http::{Request, Method};

        // Build prompt
        let system_prompt = config.get("SYSTEM_PROMPT").and_then(|v| v.as_str()).unwrap_or("You are a helpful assistant.");
        let prompt = format!("{}\n\nUser: {}\nAssistant:", system_prompt, input);

        // Prepare API request
        let api_url = config.get("API_URL").and_then(|v| v.as_str()).unwrap_or("https://api.openai.com/v1/chat/completions");

        // Retrieve the API key from the Talos secrets store at runtime.
        // This ensures the key is never compiled into the WASM binary.
        let api_key_secret_path = config.get("API_KEY_SECRET").and_then(|v| v.as_str()).unwrap_or("talos/openai_key");
        let api_key = talos::core::secrets::get_secret(api_key_secret_path)
            .map_err(|e| format!("Failed to retrieve API key secret '{}': {}", api_key_secret_path, e))?;

        let body = serde_json::json!({
            "model": config.get("MODEL").and_then(|v| v.as_str()).unwrap_or("gpt-4"),
            "messages": [
                {
                    "role": "system",
                    "content": config.get("SYSTEM_PROMPT").and_then(|v| v.as_str()).unwrap_or("You are a helpful assistant.")
                },
                {
                    "role": "user",
                    "content": input
                }
            ],
            "max_tokens": config.get("MAX_TOKENS").and_then(|v| v.as_u64()).unwrap_or(1024)
        });

        let request = Request {
            method: Method::Post,
            url: api_url.to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Authorization".to_string(), format!("Bearer {}", api_key)),
            ],
            body: serde_json::to_vec(&body).unwrap(),
            timeout_ms: Some(30000),
        };

        match talos::core::http::fetch(&request) {
            Ok(resp) => {
                let body_str = String::from_utf8(resp.body)
                    .map_err(|_| "Invalid UTF-8 in response".to_string())?;

                // Parse response and extract message
                let response: serde_json::Value = serde_json::from_str(&body_str)
                    .map_err(|e| format!("Invalid JSON response: {}", e))?;

                let content = response
                    .get("choices")
                    .and_then(|c| c.get(0))
                    .and_then(|c| c.get("message"))
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str())
                    .ok_or("Failed to extract message from response")?;

                Ok(content.to_string())
            }
            Err(_) => Err("HTTP request to LLM API failed — check API_URL, API_KEY, and host allowlist".to_string())
        }
    }
