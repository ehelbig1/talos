use serde::Deserialize;
use talos_sdk_macros::talos_module;

// RFC 0011 Smart Classifier — the single-item, self-improving classify node.
//
// Classifies one input into one of the configured LABELS by consulting the
// distilled model first (model::predict-batch, gated server-side), falling
// back to the LLM when the model abstains, and emitting an __ml_distill__
// envelope for LLM-labeled inputs so the model learns from production. While
// the model is llm_only/shadow the gate makes it abstain, so this behaves
// exactly like a plain LLM classify node; once it earns hybrid/fast_primary
// it serves the confident majority and the LLM handles only the hard tail.
//
// The model + dataset + policy are provisioned once (ml_provision_classifier)
// and referenced here by MODEL_NAME. Behavior degrades soft: a model error →
// LLM handles it; an LLM error → fail loud (nothing was classified).
//
// Contract: classifies `input.text` (or a bare-string input); emits
// { "label", "confidence", "_source" } (+ __ml_distill__ when LLM-labeled).

fn cfg_str<'a>(data: &'a serde_json::Value, key: &str, default: &'a str) -> String {
    data["config"][key]
        .as_str()
        .or_else(|| data[key].as_str())
        .unwrap_or(default)
        .to_string()
}

/// The label set the classifier may emit — from config; the model's and the
/// LLM's answers are both validated against it before they leave this node.
fn config_labels(data: &serde_json::Value) -> Vec<String> {
    let arr = if data["config"]["LABELS"].is_array() {
        &data["config"]["LABELS"]
    } else {
        &data["LABELS"]
    };
    arr.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The text to classify: `input.text`, a bare-string input, root `text`, or
/// the whole input serialized as a last resort.
fn input_text(data: &serde_json::Value) -> String {
    if let Some(s) = data["input"]["text"].as_str() {
        s.to_string()
    } else if let Some(s) = data["input"].as_str() {
        s.to_string()
    } else if let Some(s) = data["text"].as_str() {
        s.to_string()
    } else {
        serde_json::to_string(&data["input"]).unwrap_or_default()
    }
}

/// First balanced top-level JSON object in `s`, string/escape-aware.
fn balanced_object(s: &str) -> Option<&str> {
    let start = s.find('{')?;
    let bytes = s.as_bytes();
    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for (i, &b) in bytes[start..].iter().enumerate() {
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else {
            match b {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&s[start..start + i + 1]);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[derive(Deserialize)]
struct LlmLabel {
    label: String,
}

/// Scan every top-level `{` for the first object that yields a `{label}` —
/// robust to a `<think>` preamble or prose the local model may emit.
fn parse_llm_label(s: &str) -> Option<String> {
    let mut from = 0usize;
    while from < s.len() {
        let rel = s[from..].find('{')?;
        let start = from + rel;
        let obj = balanced_object(&s[start..])?;
        if let Ok(parsed) = serde_json::from_str::<LlmLabel>(obj) {
            return Some(parsed.label.trim().to_string());
        }
        from = start + 1;
    }
    None
}

fn provider_from(s: &str) -> talos::core::llm::Provider {
    use talos::core::llm::Provider;
    match s {
        "anthropic" => Provider::Anthropic,
        "openai" => Provider::Openai,
        "gemini" => Provider::Gemini,
        _ => Provider::Ollama,
    }
}

fn llm_classify(
    provider: talos::core::llm::Provider,
    llm_model: &str,
    system_prompt: &str,
    max_tokens: u32,
    labels: &[String],
    text: &str,
) -> Result<String, String> {
    // Instruct the model to answer with exactly one of the allowed labels as
    // JSON; the email/text is spotlighted as untrusted (anti-injection).
    let sys = format!(
        "{system_prompt}\n\nClassify the input into EXACTLY ONE of these labels: [{}]. \
         Respond with ONLY JSON: {{\"label\": \"<one label>\"}}.",
        labels.join(", ")
    );
    let user_content = format!("<untrusted_data>\n{text}\n</untrusted_data>");
    let req = talos::core::llm::CompletionRequest {
        provider: Some(provider),
        model: Some(llm_model.to_string()),
        messages: vec![talos::core::llm::Message {
            role: talos::core::llm::Role::User,
            content: user_content,
        }],
        max_tokens: Some(max_tokens),
        temperature: Some(0.1),
        system_prompt: Some(sys),
    };
    let options = r#"{"think":false,"keep_alive":"3h","response_format":{"type":"json_object"}}"#;
    let resp = talos::core::llm::complete_with_options(&req, Some(options))
        .map_err(|e| format!("LLM classify failed: {e:?}"))?;
    parse_llm_label(&resp.text)
        .ok_or_else(|| format!("LLM output had no parseable label (len {})", resp.text.trim().len()))
}

#[talos_module(world = "agent-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;

    let model_name = cfg_str(&data, "MODEL_NAME", "");
    if model_name.trim().is_empty() {
        return Err("Missing MODEL_NAME config".to_string());
    }
    let system_prompt = cfg_str(&data, "SYSTEM_PROMPT", "");
    if system_prompt.trim().is_empty() {
        return Err("Missing SYSTEM_PROMPT config".to_string());
    }
    let labels = config_labels(&data);
    if labels.len() < 2 {
        return Err("Missing LABELS config (need 2+ labels)".to_string());
    }
    let llm_model = cfg_str(&data, "MODEL", "qwen3.6:latest");
    let provider = provider_from(&cfg_str(&data, "PROVIDER", "ollama"));
    let max_tokens: u32 = data["config"]["MAX_TOKENS"]
        .as_u64()
        .or_else(|| data["MAX_TOKENS"].as_u64())
        .unwrap_or(256) as u32;

    let text = input_text(&data);
    if text.trim().is_empty() {
        return Err("no input text to classify".to_string());
    }
    // Optional dedup key from the upstream item's id (keeps repeated inputs
    // from bloating the dataset); omitted when absent.
    let example_key = data["input"]["id"].as_str().map(|s| s.to_string());

    // 1. Model first (gated). An error / abstain / out-of-set label → the
    // LLM handles it (soft degradation).
    let model_pred = match talos::core::model::predict_batch(&model_name, &[text.clone()]) {
        Ok(reply) => reply.predictions.into_iter().next().flatten(),
        Err(_) => None,
    };
    let model_label = model_pred
        .as_ref()
        .filter(|p| labels.contains(&p.label))
        .map(|p| (p.label.clone(), p.confidence));

    if let Some((label, confidence)) = model_label {
        // Model served — no distillation (never distill the model's own
        // predictions back into its dataset).
        return serde_json::to_string(&serde_json::json!({
            "label": label,
            "confidence": confidence,
            "_source": "model",
        }))
        .map_err(|e| e.to_string());
    }

    // 2. LLM fallback. Validate the answer is in the label set.
    let raw = llm_classify(provider, &llm_model, &system_prompt, max_tokens, &labels, &text)?;
    let label = if labels.contains(&raw) {
        raw
    } else {
        // Tolerate case/format drift by matching case-insensitively; else
        // fail loud (an out-of-set label must not reach the dataset).
        match labels.iter().find(|l| l.eq_ignore_ascii_case(&raw)) {
            Some(l) => l.clone(),
            None => {
                return Err(format!(
                    "LLM returned a label '{raw}' outside the configured set"
                ))
            }
        }
    };

    // Teacher signal → active-learning append (LLM-labeled only). A null
    // example_key deserializes to `None` in the distill validator, so the
    // absent-id case needs no special handling.
    let out = serde_json::json!({
        "label": label,
        "confidence": 1.0,
        "_source": "llm",
        "__ml_distill__": {
            "model": model_name,
            "items": [{
                "features_text": text,
                "label": label,
                "example_key": example_key,
            }],
        },
    });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}
