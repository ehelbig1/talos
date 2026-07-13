use serde::Deserialize;
use talos_sdk_macros::talos_module;

// RFC 0011 hybrid-serve classifier — the reference consumer of the
// lifecycle-gated model-serving path. Consults the distilled model first
// (model::predict-batch, gated server-side: it abstains on every message
// until the model reaches hybrid/fast_primary), then runs the LLM ONLY
// on the messages the model did not confidently serve. Emits the SAME
// {classifications:[{idx,bucket}]} shape the plain LLM classify node did
// — so the downstream organize node is unchanged — plus an __ml_distill__
// envelope for the LLM-labeled subset only (the genuine teacher signal;
// distilling the model's own predictions would be a self-reinforcing
// feedback loop).
//
// Behavior by lifecycle state (enforced by the server-side gate):
//   shadow / llm_only   → model abstains on all → LLM classifies all
//                         (identical to the pre-hybrid organizer).
//   hybrid/fast_primary → model serves confident messages, LLM handles
//                         the rest; an all-confident batch skips the LLM
//                         call entirely.
//
// Degradation posture (both legs fail SOFT, never lose the other's work):
//   - model error       → treat as abstain-all → LLM handles the batch.
//   - LLM error, model served some → emit the model's classifications
//                         (organize no-ops on the unclassified rest); the
//                         organizer re-runs next schedule.
//   - LLM error, model served nothing → fail LOUD (nothing was done, so
//                         a persistently broken LLM must surface, not
//                         silently no-op an empty inbox).
//
// Inbox contract: upstream feeds {messages:[{idx,id,subject,from,snippet}],
// few_shot:[...]} and the label space is exactly the ALLOWED_LABELS set.

/// The only buckets the organizer understands. The model's and the LLM's
/// answers are BOTH validated against this — an out-of-set label from
/// either would poison the dataset and confuse the mutating organize node.
const ALLOWED_LABELS: &[&str] = &["follow_up", "to_read", "archive"];
/// Batch cap = the predict RPC's MAX_INPUTS. Larger inputs would make the
/// model call fail wholesale; cap so the excess degrades to the LLM.
const MAX_ITEMS: usize = 32;

#[derive(Deserialize)]
struct Msg {
    idx: i64,
    id: Option<String>,
    subject: Option<String>,
    from: Option<String>,
    snippet: Option<String>,
}

#[derive(Deserialize)]
struct LlmOut {
    classifications: Vec<LlmClass>,
}

#[derive(Deserialize)]
struct LlmClass {
    idx: i64,
    bucket: String,
}

fn cfg_str<'a>(data: &'a serde_json::Value, key: &str, default: &'a str) -> String {
    data["config"][key]
        .as_str()
        .or_else(|| data[key].as_str())
        .unwrap_or(default)
        .to_string()
}

fn feature_text(m: &Msg) -> String {
    format!(
        "Subject: {}\nFrom: {}\nSnippet: {}",
        m.subject.as_deref().unwrap_or(""),
        m.from.as_deref().unwrap_or(""),
        m.snippet.as_deref().unwrap_or("")
    )
}

/// Return the first balanced top-level JSON object in `s` (starting at
/// its first `{`), string/escape-aware. `None` if no `{` or unbalanced.
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

/// Extract the classify JSON from a model response — robust to a
/// `<think>` preamble, markdown fences, or trailing prose. Scans EVERY
/// top-level `{` and returns the first balanced object that actually
/// deserializes into the classify shape; a single first-brace anchor
/// would lock onto a brace inside the reasoning preamble and fail.
fn parse_llm_out(s: &str) -> Option<LlmOut> {
    let mut from = 0usize;
    while from < s.len() {
        let rel = s[from..].find('{')?;
        let start = from + rel;
        let obj = balanced_object(&s[start..])?;
        if let Ok(parsed) = serde_json::from_str::<LlmOut>(obj) {
            return Some(parsed);
        }
        // This `{` didn't yield a valid classify object; advance past it.
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

/// Run the LLM leg over the abstained subset. Returns the parsed
/// classify output, or a human-readable error the caller decides how to
/// treat (fail-loud vs partial-emit).
fn run_llm_leg(
    provider: talos::core::llm::Provider,
    llm_model: &str,
    system_prompt: &str,
    max_tokens: u32,
    llm_subset: &[serde_json::Value],
    few_shot: &serde_json::Value,
) -> Result<LlmOut, String> {
    let user_payload = serde_json::json!({
        "messages": llm_subset,
        "few_shot": few_shot,
    });
    // Spotlight the untrusted email content (anti-injection posture, same
    // as the LLM_Inference node's SPOTLIGHTING default). serde_json
    // serialization escapes any braces/quotes in the email so it cannot
    // break out of the JSON string context.
    let user_content = format!(
        "<untrusted_data>\n{}\n</untrusted_data>",
        serde_json::to_string(&user_payload).map_err(|e| e.to_string())?
    );
    let req = talos::core::llm::CompletionRequest {
        provider: Some(provider),
        model: Some(llm_model.to_string()),
        messages: vec![talos::core::llm::Message {
            role: talos::core::llm::Role::User,
            content: user_content,
        }],
        max_tokens: Some(max_tokens),
        temperature: Some(0.1),
        system_prompt: Some(system_prompt.to_string()),
    };
    // think:false is the native Ollama switch to disable qwen3 reasoning
    // (the raw llm WIT / in-prompt /no_think don't take); keep_alive keeps
    // the model resident; response_format forces JSON. Same passthrough
    // the LLM_Inference node used.
    let options = r#"{"think":false,"keep_alive":"3h","response_format":{"type":"json_object"}}"#;
    let resp = talos::core::llm::complete_with_options(&req, Some(options))
        .map_err(|e| format!("LLM classify failed: {e:?}"))?;
    parse_llm_out(&resp.text).ok_or_else(|| {
        format!(
            "LLM output had no parseable classifications JSON (len {})",
            resp.text.trim().len()
        )
    })
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
    let llm_model = cfg_str(&data, "MODEL", "qwen3.6:latest");
    let provider = provider_from(&cfg_str(&data, "PROVIDER", "ollama"));
    let max_tokens: u32 = data["config"]["MAX_TOKENS"]
        .as_u64()
        .or_else(|| data["MAX_TOKENS"].as_u64())
        .unwrap_or(1800) as u32;

    // Upstream (feedback) output: {messages, few_shot}. Read from the
    // direct input, falling back to the accumulated feedback node.
    let upstream = if data["input"]["messages"].is_array() {
        &data["input"]
    } else {
        &data["__accumulated__"]["feedback"]
    };
    // A PRESENT-but-malformed messages array is a contract break — fail
    // loud rather than silently classifying nothing. `unwrap_or_default`
    // here would mask a renamed upstream field / shape drift as an empty
    // inbox, which reads as "everything handled" and stalls the organizer.
    let mut messages: Vec<Msg> = if upstream["messages"].is_array() {
        serde_json::from_value(upstream["messages"].clone())
            .map_err(|e| format!("upstream messages array malformed: {e}"))?
    } else {
        Vec::new()
    };
    let few_shot = upstream["few_shot"].clone();
    if messages.is_empty() {
        return Ok(serde_json::json!({
            "classifications": [],
            "_hybrid": {"model_served": 0, "llm_served": 0, "total": 0}
        })
        .to_string());
    }
    // Bound the batch: the model RPC caps at MAX_ITEMS and would fail the
    // whole call past it; truncating keeps the model path usable and the
    // tail simply isn't classified this run (the organizer re-runs).
    messages.truncate(MAX_ITEMS);
    // Guard the idx-keyed merge below against a duplicate upstream idx: a
    // collision would cross-contaminate served_idx / by_idx and could
    // attach the wrong email's text to a distilled training example. Keep
    // the first occurrence.
    {
        let mut seen = std::collections::HashSet::new();
        messages.retain(|m| seen.insert(m.idx));
    }

    // 1. Ask the distilled model. A model error (not promoted, serving
    // path down, emptied dataset) is NOT fatal — treat it as "abstained
    // on everything" so the LLM handles the batch (graceful degradation).
    let features: Vec<String> = messages.iter().map(feature_text).collect();
    let predictions: Vec<Option<talos::core::model::Prediction>> =
        match talos::core::model::predict_batch(&model_name, &features) {
            Ok(reply) => reply.predictions,
            // Cancellation is a directive, not a serving failure — the WIT
            // contract says "do NOT retry; unwind". Falling through would
            // burn a full LLM batch for an execution the operator killed.
            Err(talos::core::model::Error::Cancelled) => {
                return Err("Execution cancelled — not retrying".to_string())
            }
            Err(_) => messages.iter().map(|_| None).collect(),
        };

    // 2. Split: model-served (confident + in-set label) vs. abstained.
    // `served_idx` guards the merge against a duplicate/foreign idx from
    // the LLM downstream.
    let mut classifications: Vec<serde_json::Value> = Vec::with_capacity(messages.len());
    let mut served_idx: std::collections::HashSet<i64> = std::collections::HashSet::new();
    let mut model_served = 0usize;
    let mut llm_subset: Vec<serde_json::Value> = Vec::new();
    for (i, m) in messages.iter().enumerate() {
        // A model label outside the allowed set is treated as an
        // abstention (defensive — the promoted model should only emit
        // dataset labels, but a stale/mis-trained version must not push
        // a junk bucket into the mutating organize node).
        let served = predictions
            .get(i)
            .and_then(|p| p.as_ref())
            .filter(|p| ALLOWED_LABELS.contains(&p.label.as_str()));
        match served {
            Some(p) => {
                classifications.push(serde_json::json!({"idx": m.idx, "bucket": p.label}));
                served_idx.insert(m.idx);
                model_served += 1;
            }
            None => {
                // Preserve the ORIGINAL idx so the LLM's index-based
                // answer merges back correctly.
                llm_subset.push(serde_json::json!({
                    "idx": m.idx,
                    "id": m.id,
                    "subject": m.subject,
                    "from": m.from,
                    "snippet": m.snippet,
                }));
            }
        }
    }

    // 3. LLM only on the abstained subset (skipped entirely when the
    // model served everything).
    let mut llm_served = 0usize;
    let mut llm_dropped = 0usize;
    let mut llm_error: Option<String> = None;
    let mut distill_items: Vec<serde_json::Value> = Vec::new();
    if !llm_subset.is_empty() {
        // The set of idx we actually asked the LLM about — a returned idx
        // NOT in here (hallucinated) is dropped rather than trusted.
        let asked: std::collections::HashSet<i64> =
            llm_subset.iter().filter_map(|m| m["idx"].as_i64()).collect();
        let asked_count = asked.len();
        match run_llm_leg(
            provider,
            &llm_model,
            &system_prompt,
            max_tokens,
            &llm_subset,
            &few_shot,
        ) {
            Ok(parsed) => {
                let mut by_idx = std::collections::HashMap::new();
                for m in &messages {
                    by_idx.insert(m.idx, m);
                }
                for c in &parsed.classifications {
                    // Drop anything we didn't ask about, a duplicate, or an
                    // out-of-set bucket — never let the LLM inject a foreign
                    // idx or a junk label into the organize/distill outputs.
                    if !asked.contains(&c.idx)
                        || served_idx.contains(&c.idx)
                        || !ALLOWED_LABELS.contains(&c.bucket.as_str())
                    {
                        continue;
                    }
                    classifications.push(serde_json::json!({"idx": c.idx, "bucket": c.bucket}));
                    served_idx.insert(c.idx);
                    llm_served += 1;
                    if let Some(m) = by_idx.get(&c.idx) {
                        // Teacher signal for the hard cases → active-learning
                        // append. Only the LLM-labeled subset is distilled.
                        distill_items.push(serde_json::json!({
                            "features_text": feature_text(m),
                            "label": c.bucket,
                            "example_key": m.id,
                        }));
                    }
                }
                // Abstained messages the LLM silently omitted are left
                // unclassified this run (organize no-ops on them; the
                // organizer re-runs). Surface the count for observability.
                llm_dropped = asked_count.saturating_sub(llm_served);
            }
            Err(e) => {
                // Graceful degradation: if the model already served some
                // messages, emit those (partial success — organize no-ops
                // on the unclassified rest). Only fail LOUD when nothing
                // was accomplished, so a persistently broken LLM surfaces
                // instead of silently no-op'ing an empty inbox.
                if classifications.is_empty() {
                    return Err(format!("LLM classify failed and model served nothing: {e}"));
                }
                llm_dropped = asked_count;
                llm_error = Some(e);
            }
        }
    }

    // Stable output order regardless of the model/LLM split.
    classifications.sort_by_key(|c| c["idx"].as_i64().unwrap_or(0));

    let mut out = serde_json::json!({
        "classifications": classifications,
        "_hybrid": {
            "model_served": model_served,
            "llm_served": llm_served,
            "llm_dropped": llm_dropped,
            "total": messages.len(),
            "llm_skipped": llm_subset.is_empty(),
            "llm_error": llm_error,
        }
    });
    // Emit the distill envelope only when there is genuine new teacher
    // signal (an all-model-served batch, or a failed LLM leg, teaches the
    // model nothing new).
    if !distill_items.is_empty() {
        out["__ml_distill__"] = serde_json::json!({
            "model": model_name,
            "items": distill_items,
        });
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}
