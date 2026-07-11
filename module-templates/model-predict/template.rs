// Model Predict — batch inference against a registered platform ML model
// (RFC 0011). The guest never touches the dataset or any credential: it
// calls `talos::core::model::predict-batch`, the host signs an RPC to the
// controller, and the controller resolves the model under the EXECUTION
// USER's tenancy and serves the promoted version. Inference is host-local
// (local embeddings + in-Postgres ANN) — Tier-1-clean by construction.
//
// The distillation consumer pattern: run this node on the same items an
// LLM classify node handles; slots where the model ABSTAINS (null) — or
// falls below CONFIDENCE_THRESHOLD — are the ones to route to the LLM
// fallback branch. `abstained_idx` lists them for a downstream filter.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

/// Protocol batch cap (talos_memory::ml_rpc::MAX_INPUTS).
const RPC_BATCH: usize = 32;
/// Hard cap on items per run — bounds fuel AND the controller-side
/// embed+ANN work one node execution can queue.
const HARD_MAX_ITEMS: usize = 512;
/// Protocol per-input byte cap (talos_memory::ml_rpc::MAX_INPUT_BYTES).
const MAX_FEATURE_BYTES: usize = 16 * 1024;

#[derive(Deserialize, Default)]
struct Config {
    #[serde(rename = "MODEL_NAME")]
    model_name: Option<String>,
    #[serde(rename = "INPUT_PATH")]
    input_path: Option<String>,
    #[serde(rename = "FEATURE_TEMPLATE")]
    feature_template: Option<String>,
    #[serde(rename = "CONFIDENCE_THRESHOLD")]
    confidence_threshold: Option<f32>,
    #[serde(rename = "MAX_ITEMS")]
    max_items: Option<usize>,
}

/// UTF-8-safe byte truncation (never slices inside a multi-byte
/// codepoint — the `&str[..N]` panic class).
fn truncate_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Dotted-path lookup into a JSON value ("a.b.c").
fn lookup<'a>(v: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Minimal `{{key}}` / `{{key.sub}}` interpolation against one item.
/// Strings inline; other values JSON-serialize; unresolved placeholders
/// stay as-is so misconfiguration surfaces visibly (llm-inference
/// convention).
fn render_template(template: &str, item: &serde_json::Value) -> String {
    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let key = after[..end].trim();
        match lookup(item, key) {
            Some(serde_json::Value::String(s)) => out.push_str(s),
            Some(other) => out.push_str(&other.to_string()),
            None => {
                out.push_str("{{");
                out.push_str(key);
                out.push_str("}}");
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Feature text for one item: template if configured, else strings
/// pass through and objects JSON-serialize.
fn feature_text(item: &serde_json::Value, template: Option<&str>) -> String {
    let raw = match template {
        Some(t) => render_template(t, item),
        None => match item {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        },
    };
    truncate_bytes(&raw, MAX_FEATURE_BYTES).to_string()
}

fn model_error_message(err: talos::core::model::Error, model_name: &str) -> String {
    use talos::core::model::Error;
    match err {
        Error::NotFound => format!(
            "Model '{model_name}' not found for this execution's user — register it with ml_create_model (or check MODEL_NAME)"
        ),
        Error::NotPromoted => format!(
            "Model '{model_name}' has no promoted version — run ml_eval_model + ml_promote_model first"
        ),
        Error::NotAvailable => format!(
            "Model '{model_name}' can't serve right now: unsupported backend, empty dataset, or the ML serving path is not configured on this deployment"
        ),
        Error::InvalidInput => {
            "Invalid predict request (empty/oversized model name or inputs, or no execution user context)".to_string()
        }
        Error::Timeout => "Model predict timed out — retry or check controller load".to_string(),
        Error::RateLimited => {
            "Per-execution model-predict budget exhausted — reduce items per run".to_string()
        }
        Error::Internal => "Model predict failed internally — see controller logs".to_string(),
    }
}

#[talos_module(world = "secrets-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::model::predict_batch;

    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config: Config = data
        .get("config")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("Invalid config: {e}"))?
        .unwrap_or_default();

    let model_name = config
        .model_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("Missing MODEL_NAME config (the registered ml_models name to serve)")?;

    // Locate the item array: INPUT_PATH first, then conventional keys,
    // then a bare top-level array.
    let items: Vec<serde_json::Value> = if let Some(path) = config.input_path.as_deref() {
        lookup(&data, path)
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| format!("INPUT_PATH '{path}' does not resolve to an array"))?
    } else {
        ["inputs", "items", "messages"]
            .iter()
            .find_map(|k| data.get(*k).and_then(|v| v.as_array()).cloned())
            .or_else(|| data.as_array().cloned())
            .unwrap_or_default()
    };

    if items.is_empty() {
        // Graceful empty result — no upstream data is not an error.
        return Ok(serde_json::json!({
            "predictions": [],
            "abstained_idx": [],
            "total": 0,
            "predicted": 0,
            "abstained": 0,
        })
        .to_string());
    }

    let max_items = config.max_items.unwrap_or(200).clamp(1, HARD_MAX_ITEMS);
    let items = &items[..items.len().min(max_items)];
    let features: Vec<String> = items
        .iter()
        .map(|it| feature_text(it, config.feature_template.as_deref()))
        .collect();

    // Batch through the protocol cap; slot order is preserved.
    let mut slots = Vec::with_capacity(features.len());
    let mut model_version: i32 = 0;
    let mut backend = String::new();
    for chunk in features.chunks(RPC_BATCH) {
        let reply = predict_batch(model_name, chunk)
            .map_err(|e| model_error_message(e, model_name))?;
        if reply.predictions.len() != chunk.len() {
            return Err("Model predict reply shape mismatch (slot count)".to_string());
        }
        model_version = reply.model_version;
        backend = reply.backend;
        slots.extend(reply.predictions);
    }

    let threshold = config.confidence_threshold.unwrap_or(0.0);
    let mut abstained_idx = Vec::new();
    let predictions: Vec<serde_json::Value> = slots
        .into_iter()
        .enumerate()
        .map(|(idx, slot)| match slot {
            Some(p) if p.confidence >= threshold => serde_json::json!({
                "idx": idx,
                "label": p.label,
                "confidence": p.confidence,
            }),
            // Abstained (or below the calibrated threshold): the
            // caller's LLM fallback branch owns this item.
            _ => {
                abstained_idx.push(idx);
                serde_json::Value::Null
            }
        })
        .collect();

    let predicted = predictions.iter().filter(|p| !p.is_null()).count();
    let abstained = abstained_idx.len();
    Ok(serde_json::json!({
        "predictions": predictions,
        "abstained_idx": abstained_idx,
        "model_version": model_version,
        "backend": backend,
        "total": items.len(),
        "predicted": predicted,
        "abstained": abstained,
    })
    .to_string())
}
