use anyhow::{anyhow, Result};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tracing::{error, warn};

#[derive(Clone)]
pub struct LlmClient {
    client: Client,
    api_key: String,
}

impl LlmClient {
    pub fn new(api_key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self { client, api_key }
    }

    pub async fn generate_code(
        &self,
        prompt: &str,
        current_code: &str,
        capability_world: &str,
    ) -> Result<String> {
        let system_prompt = format!(
            "You are an expert Rust WebAssembly module developer. \
            Generate or modify the code based on the user's prompt. \
            The module runs in the '{}' world. \
            \
            CRITICAL RULES:\n\
            1. ONLY output valid Rust code. Do not include markdown formatting like ```rust, just the raw code.\n\
            2. ALWAYS include the `use talos_sdk_macros::talos_node;` statement at the very top of the file.\n\
            3. Any additional `use` statements (like `use std::net::ToSocketAddrs;`) MUST be placed at the top of the file, BEFORE the `#[talos_node]` macro.\n\
            4. ALWAYS apply the `#[talos_node(world = \"...\")]` macro directly above the `pub fn run` function.\n\
            5. DO NOT use or import `talos_sdk`. It does not exist in this environment. Use standard Rust standard library and external crates if network access is allowed.",
            capability_world
        );

        let user_prompt = format!("Current code:\n{}\n\nPrompt: {}", current_code, prompt);

        let mut retries = 0;
        let max_retries = 3;

        let response = loop {
            let req = self
                .client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .json(&json!({
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 4096,
                    "system": &system_prompt,
                    "messages": [
                        {
                            "role": "user",
                            "content": &user_prompt
                        }
                    ]
                }));

            let resp = req.send().await?;

            if resp.status().is_success() {
                break resp;
            }

            let status = resp.status();

            // Retry on 529 Overloaded or other 5xx server errors
            if status.as_u16() == 529 || status.is_server_error() || status.as_u16() == 429 {
                if retries >= max_retries {
                    let text = resp.text().await.unwrap_or_default();
                    error!("Anthropic API error after {} retries: {}", retries, text);
                    return Err(anyhow!("Failed to generate code from LLM API: {}", text));
                }

                retries += 1;
                let backoff_secs = 2_u64.pow(retries);
                warn!(
                    "Anthropic API returned {}. Retrying in {}s... ({}/{})",
                    status, backoff_secs, retries, max_retries
                );
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                continue;
            }

            // Non-retriable error
            let text = resp.text().await.unwrap_or_default();
            error!("Anthropic API error {}: {}", status, text);
            return Err(anyhow!("Failed to generate code from LLM API: {}", text));
        };

        let body: serde_json::Value = response.json().await?;

        let mut text = body["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // Strip control characters
        text.retain(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t');

        if text.starts_with("```rust") {
            text = text.trim_start_matches("```rust").to_string();
        } else if text.starts_with("```") {
            text = text.trim_start_matches("```").to_string();
        }
        if text.ends_with("```") {
            text = text.trim_end_matches("```").to_string();
        }

        Ok(text.trim().to_string())
    }
}
