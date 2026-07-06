use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    use talos::core::http::{Request, Method};

    // ── Config extraction ──────────────────────────────────────────────────────

    // CONSTITUTION: required. Newline-separated principles; empty lines are skipped.
    let constitution_raw = config
        .get("CONSTITUTION")
        .and_then(|v| v.as_str())
        .ok_or("CONSTITUTION config key is required but was not set")?;
    let principles: Vec<&str> = constitution_raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if principles.is_empty() {
        return Err(
            "CONSTITUTION config key is set but contains no non-empty lines. \
             Provide at least one principle (one per line)."
                .to_string(),
        );
    }

    // MAX_ROUNDS: 1–5, default 3.
    let max_rounds_raw = config
        .get("MAX_ROUNDS")
        .and_then(|v| v.as_f64())
        .unwrap_or(3.0);
    if max_rounds_raw.fract() != 0.0 {
        return Err(format!(
            "MAX_ROUNDS must be a whole number, got {max_rounds_raw}"
        ));
    }
    let max_rounds = max_rounds_raw as u64;
    if max_rounds < 1 || max_rounds > 5 {
        return Err(format!(
            "MAX_ROUNDS must be between 1 and 5, got {max_rounds}"
        ));
    }

    // MAX_TOKENS: default 1024.
    let max_tokens = config
        .get("MAX_TOKENS")
        .and_then(|v| v.as_u64())
        .unwrap_or(1024);

    // PROVIDER: "openai" (default) or "anthropic".
    let provider = config
        .get("PROVIDER")
        .and_then(|v| v.as_str())
        .unwrap_or("openai");
    if provider != "openai" && provider != "anthropic" {
        return Err(format!(
            "PROVIDER must be 'openai' or 'anthropic', got '{provider}'"
        ));
    }

    // MODEL: provider-aware default.
    let default_model = if provider == "anthropic" {
        "claude-sonnet-4-6"
    } else {
        "gpt-4o-mini"
    };
    let model = config
        .get("MODEL")
        .and_then(|v| v.as_str())
        .unwrap_or(default_model);

    // CRITIQUE_PROMPT: optional extra instruction.
    let critique_extra = config
        .get("CRITIQUE_PROMPT")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // API_KEY_SECRET: vault path for the LLM key.
    let api_key_secret_path = config
        .get("API_KEY_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("API_KEY_SECRET config key is required but was not set")?;

    // ── Input extraction ───────────────────────────────────────────────────────

    // Primary input: data["input"] (standard inter-node propagation).
    // Falls back to __trigger_input__["input"] when the module is the first node
    // and the trigger has not been transformed by a preceding node.
    let raw_input = input_json
        .get("input")
        .or_else(|| {
            input_json
                .get("__trigger_input__")
                .and_then(|t| t.get("input"))
        })
        .and_then(|v| v.as_str())
        .ok_or(
            "data[\"input\"] is required but was not found. \
             Connect an upstream node or pass {\"input\": \"<text>\"} as the trigger input.",
        )?;

    // ── Vault key resolution (Tier-1: plaintext never in guest memory) ─────────
    let api_key_slot = talos::core::secrets::get_secret(api_key_secret_path)
        .map_err(|e| {
            format!(
                "Failed to retrieve API key secret '{api_key_secret_path}': {e}. \
                 Ensure the secret is provisioned in the dashboard (Settings → Secrets) and the vault path is correct."
            )
        })?;

    // ── Helper: strip markdown fences from LLM responses ──────────────────────
    fn defence(s: &str) -> &str {
        let t = s.trim();
        if let Some(after) = t
            .strip_prefix("```json")
            .or_else(|| t.strip_prefix("```"))
        {
            after.trim_start_matches('\n').trim_end_matches("```").trim()
        } else {
            t
        }
    }

    // ── Helper: build the critique system prompt ───────────────────────────────
    // Instructs the LLM to act as a constitutional critic and return structured JSON.
    fn build_system_prompt(principles: &[&str], extra: &str) -> String {
        let principle_list = principles
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{}. {}", i + 1, p))
            .collect::<Vec<_>>()
            .join("\n");

        let base = format!(
            "You are a constitutional AI critic. Your task is to evaluate a piece of text \
             against a set of principles and, if needed, produce a revised version that \
             satisfies all principles.\n\n\
             CONSTITUTION (principles to enforce):\n{principle_list}\n\n\
             For each critique call you will receive the current text. You must respond \
             with a raw JSON object (no markdown fences, no prose) with exactly these keys:\n\
             - \"critique\": string — explanation of which principles (if any) are violated \
               and why. If all principles are satisfied, write \"All principles satisfied.\"\n\
             - \"revision_needed\": boolean — true if ANY principle is violated, false if \
               the text already satisfies all principles.\n\
             - \"revised_output\": string — the revised text if revision_needed is true; \
               otherwise the original text unchanged.\n\n\
             IMPORTANT: respond ONLY with the raw JSON object. No additional text."
        );

        if extra.is_empty() {
            base
        } else {
            format!("{base}\n\nAdditional guidance: {extra}")
        }
    }

    // ── Helper: call OpenAI chat completions ───────────────────────────────────
    fn call_openai(
        slot: u64,
        model: &str,
        max_tokens: u64,
        system: &str,
        user_content: &str,
        timeout_ms: u32,
    ) -> Result<String, String> {
        let body = serde_json::json!({
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user_content}
            ],
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"}
        });
        let request = Request {
            method: Method::Post,
            url: "https://api.openai.com/v1/chat/completions".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: serde_json::to_vec(&body).unwrap(),
            timeout_ms: Some(timeout_ms),
        };
        let resp = talos::core::http::fetch_with_bearer(slot, &request)
            .map_err(|e| format!("Network error reaching OpenAI API: {e}"))?;
        let body_str = String::from_utf8(resp.body)
            .map_err(|_| "Invalid UTF-8 in OpenAI response".to_string())?;
        if resp.status == 401 || resp.status == 403 {
            return Err(format!(
                "OpenAI API authentication error (HTTP {}): {} — check API_KEY_SECRET.",
                resp.status,
                body_str.chars().take(400).collect::<String>()
            ));
        }
        if resp.status == 429 {
            return Err(format!(
                "OpenAI API rate limit exceeded (HTTP 429): {}",
                body_str.chars().take(300).collect::<String>()
            ));
        }
        if resp.status >= 400 {
            return Err(format!(
                "OpenAI API error (HTTP {}): {}",
                resp.status,
                body_str.chars().take(500).collect::<String>()
            ));
        }
        let response: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|e| format!("Invalid JSON from OpenAI API: {e}"))?;
        let content = response
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or("Failed to extract message content from OpenAI response")?;
        Ok(defence(content).to_string())
    }

    // ── Helper: call Anthropic messages ───────────────────────────────────────
    fn call_anthropic(
        slot: u64,
        model: &str,
        max_tokens: u64,
        system: &str,
        user_content: &str,
        timeout_ms: u32,
    ) -> Result<String, String> {
        let body = serde_json::json!({
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user_content}]
        });
        let request = Request {
            method: Method::Post,
            url: "https://api.anthropic.com/v1/messages".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("anthropic-version".to_string(), "2023-06-01".to_string()),
            ],
            body: serde_json::to_vec(&body).unwrap(),
            timeout_ms: Some(timeout_ms),
        };
        let resp = talos::core::http::fetch_with_header(slot, "x-api-key", &request)
            .map_err(|e| format!("Network error reaching Anthropic API: {e}"))?;
        let body_str = String::from_utf8(resp.body)
            .map_err(|_| "Invalid UTF-8 in Anthropic response".to_string())?;
        if resp.status == 401 || resp.status == 403 {
            return Err(format!(
                "Anthropic API authentication error (HTTP {}): {} — check API_KEY_SECRET.",
                resp.status,
                body_str.chars().take(400).collect::<String>()
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
                resp.status,
                body_str.chars().take(500).collect::<String>()
            ));
        }
        let response: serde_json::Value = serde_json::from_str(&body_str)
            .map_err(|e| format!("Invalid JSON from Anthropic API: {e}"))?;
        let content = response
            .get("content")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str())
            .ok_or("Anthropic response missing content[0].text")?;
        Ok(defence(content).to_string())
    }

    // ── Constitutional refinement loop ─────────────────────────────────────────

    let system_prompt = build_system_prompt(&principles, critique_extra);

    // Timeout per LLM call: 30 s (leaves headroom within a typical 120 s node deadline).
    let call_timeout_ms: u32 = 30_000;

    let mut current = raw_input.to_string();
    let mut revision_history: Vec<serde_json::Value> = Vec::new();
    let mut rounds_taken: u64 = 0;

    for round in 1..=max_rounds {
        // Build user message: present the current text for critique.
        let user_msg = format!(
            "Please critique the following text against the constitution and return the \
             required JSON object.\n\n<text_to_evaluate>\n{current}\n</text_to_evaluate>"
        );

        // Dispatch to the selected provider.
        let raw_response = if provider == "anthropic" {
            call_anthropic(
                api_key_slot,
                model,
                max_tokens,
                &system_prompt,
                &user_msg,
                call_timeout_ms,
            )?
        } else {
            call_openai(
                api_key_slot,
                model,
                max_tokens,
                &system_prompt,
                &user_msg,
                call_timeout_ms,
            )?
        };

        // Parse the structured critique response.
        let critique_json: serde_json::Value =
            serde_json::from_str(&raw_response).map_err(|e| {
                format!(
                    "Round {round}: LLM did not return valid JSON: {e}. \
                     Raw response (first 500 chars): {}",
                    raw_response.chars().take(500).collect::<String>()
                )
            })?;

        let critique_text = critique_json
            .get("critique")
            .and_then(|v| v.as_str())
            .unwrap_or("(no critique provided)")
            .to_string();

        // revision_needed: explicit bool, or fall back to checking the critique text.
        let revision_needed = critique_json
            .get("revision_needed")
            .and_then(|v| v.as_bool())
            .unwrap_or(!critique_text.to_lowercase().contains("all principles satisfied"));

        let revised_text = if revision_needed {
            critique_json
                .get("revised_output")
                .and_then(|v| v.as_str())
                .unwrap_or(&current)
                .to_string()
        } else {
            current.clone()
        };

        revision_history.push(serde_json::json!({
            "round": round,
            "critique": critique_text,
            "revision_needed": revision_needed,
            "revised": revised_text.clone()
        }));

        rounds_taken = round;

        if revision_needed {
            current = revised_text;
        } else {
            // All principles satisfied — stop early.
            break;
        }
    }

    // ── Assemble output ────────────────────────────────────────────────────────

    let constitution_applied: Vec<String> =
        principles.iter().map(|p| p.to_string()).collect();

    let output = serde_json::json!({
        "output": current,
        "rounds_taken": rounds_taken,
        "constitution_applied": constitution_applied,
        "revision_history": revision_history
    });

    Ok(output.to_string())
}
