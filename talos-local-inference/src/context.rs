//! Did Ollama truncate the prompt?
//!
//! When a prompt is longer than the context the model was loaded with, Ollama
//! does not refuse it: it drops the start and evaluates what is left, answers
//! HTTP 200, and says nothing in the response. Measured on the reference host
//! (Ollama 0.35.0, 2026-09-30): a 22 925-token prompt sent with
//! `num_ctx: 4096` was evaluated as **2 050** tokens and the model never saw
//! the system prompt at the head of it. The only trace is a server-log WARN,
//! `truncating input prompt limit=2050 prompt=22925 keep=4 new=2050`.
//!
//! The evaluated count is not arbitrary. At three context sizes it was exactly
//! `context / 2 + 2` (4 096 → 2 050, 8 192 → 4 098, 6 000 → 3 002), so a
//! response whose `prompt_eval_count` sits at half the loaded context is the
//! truncation's signature. The loaded context comes from `/api/ps`
//! (`context_length`), read at most once per [`PS_CACHE_TTL`] per base URL.
//!
//! This is a DETECTOR, not an authorization gate: it runs after the answer
//! exists. When the context cannot be read it returns [`PromptFit::Unknown`]
//! and the caller keeps the answer — refusing on an unreadable `/api/ps` would
//! turn a monitoring hiccup into failed workflow runs, and the answer is
//! almost always sound (no truncation has appeared in the reference host's
//! retained Ollama logs outside the experiment above).

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::locality::normalize_model_name;

/// How long one `/api/ps` answer is trusted.
pub const PS_CACHE_TTL: Duration = Duration::from_secs(30);

/// Deadline for the `/api/ps` request.
pub const PS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How far above `context / 2` a truncated prompt's evaluated count may sit.
/// Measured: exactly `+ 2` on Ollama 0.35.0; the slack keeps the check working
/// if the retained head (`keep`) changes by a few tokens.
pub const TRUNCATION_TOLERANCE: u64 = 8;

/// Below this many evaluated tokens the check is skipped: a truncation would
/// need a loaded context under 2 048 tokens, which no model here is run with.
pub const MIN_CHECKED_PROMPT_TOKENS: u64 = 1_024;

/// Whether an evaluated prompt of `prompt_eval_count` tokens, on a model
/// loaded with `context_length`, carries the truncation signature.
///
/// A genuine prompt of exactly `context/2 .. context/2 + 8` tokens would be
/// misread — at a 131 072 context, a prompt of 65 536–65 544 tokens. Stated
/// rather than engineered away: the window is nine tokens wide.
#[must_use]
pub fn truncation_signature(prompt_eval_count: u64, context_length: u64) -> bool {
    if context_length < 2 {
        return false;
    }
    let half = context_length / 2;
    (half..=half + TRUNCATION_TOLERANCE).contains(&prompt_eval_count)
}

/// What the check concluded about one prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptFit {
    /// The evaluated count does not carry the truncation signature.
    Fits,
    /// Ollama evaluated `evaluated` tokens of a prompt that did not fit the
    /// `context_length` the model was loaded with.
    Truncated { evaluated: u64, context_length: u64 },
    /// The check could not be made (context unreadable, model not loaded, or
    /// no token count). `reason` is value-free.
    Unknown { reason: &'static str },
}

type Index = HashMap<String, u64>;

fn cache() -> &'static tokio::sync::Mutex<HashMap<String, (Instant, Index)>> {
    static CACHE: OnceLock<tokio::sync::Mutex<HashMap<String, (Instant, Index)>>> = OnceLock::new();
    CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

/// `normalized name -> context_length` from an `/api/ps` body.
fn index_ps(ps: &serde_json::Value) -> Option<Index> {
    let models = ps.get("models")?.as_array()?;
    let mut out = Index::new();
    for m in models {
        let Some(ctx) = m.get("context_length").and_then(|c| c.as_u64()) else {
            continue;
        };
        for key in ["name", "model"] {
            if let Some(n) = m.get(key).and_then(|n| n.as_str()) {
                out.insert(normalize_model_name(n), ctx);
            }
        }
    }
    Some(out)
}

async fn fetch_ps(client: &reqwest::Client, base_url: &str) -> Option<Index> {
    let resp = client
        .get(format!("{}/api/ps", base_url.trim_end_matches('/')))
        .timeout(PS_FETCH_TIMEOUT)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = talos_http_body::read_json_capped(resp).await.ok()?;
    index_ps(&body)
}

/// The context `model` is loaded with, per `/api/ps` at `base_url`: `Ok(None)`
/// when it is not loaded, `Err(())` when `/api/ps` could not be read. Cached
/// per base URL for [`PS_CACHE_TTL`], re-read once when a cached listing lacks
/// the model (it may have loaded since).
async fn loaded_context_length(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
) -> Result<Option<u64>, ()> {
    let key = normalize_model_name(model);
    let mut guard = cache().lock().await;
    if let Some((at, index)) = guard.get(base_url) {
        if at.elapsed() < PS_CACHE_TTL {
            if let Some(ctx) = index.get(&key) {
                return Ok(Some(*ctx));
            }
        }
    }
    let index = fetch_ps(client, base_url).await.ok_or(())?;
    let answer = index.get(&key).copied();
    guard.insert(base_url.to_string(), (Instant::now(), index));
    Ok(answer)
}

/// Check one finished local exchange: did Ollama truncate its prompt?
///
/// `prompt_eval_count` is the response's own count. Small prompts
/// ([`MIN_CHECKED_PROMPT_TOKENS`]) are skipped without a request.
pub async fn check_prompt_fit(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
    prompt_eval_count: Option<u64>,
) -> PromptFit {
    let Some(evaluated) = prompt_eval_count else {
        return PromptFit::Unknown {
            reason: "no prompt_eval_count in the response",
        };
    };
    if evaluated < MIN_CHECKED_PROMPT_TOKENS {
        return PromptFit::Fits;
    }
    match loaded_context_length(client, base_url, model).await {
        Ok(Some(context_length)) if truncation_signature(evaluated, context_length) => {
            PromptFit::Truncated {
                evaluated,
                context_length,
            }
        }
        Ok(Some(_)) => PromptFit::Fits,
        Ok(None) => PromptFit::Unknown {
            reason: "model not loaded",
        },
        Err(()) => PromptFit::Unknown {
            reason: "/api/ps unreadable",
        },
    }
}

/// The sentence a caller reports for [`PromptFit::Truncated`]. Value-free: it
/// names counts and the remedy, never prompt text.
#[must_use]
pub fn truncation_message(model: &str, evaluated: u64, context_length: u64) -> String {
    let model: String = model.trim().chars().take(128).collect();
    format!(
        "Ollama truncated the prompt: model `{model}` is loaded with a {context_length}-token \
         context and evaluated only {evaluated} tokens of a longer prompt, dropping its start \
         (including the system prompt). The answer was not used. Shorten the input, or raise \
         the context (OLLAMA_CONTEXT_LENGTH on the Ollama host, or options.num_ctx)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The three measured points, and their neighbours.
    #[test]
    fn the_measured_truncations_carry_the_signature() {
        assert!(truncation_signature(2_050, 4_096));
        assert!(truncation_signature(4_098, 8_192));
        assert!(truncation_signature(3_002, 6_000));
        // A full prompt that fit, and counts just outside the window.
        assert!(!truncation_signature(22_925, 32_768));
        assert!(!truncation_signature(2_047, 4_096));
        assert!(!truncation_signature(2_057, 4_096));
        assert!(!truncation_signature(0, 0));
    }

    #[test]
    fn ps_is_indexed_by_normalized_name() {
        let ps = json!({"models": [
            {"name": "qwen3.6:latest", "model": "qwen3.6:latest", "context_length": 131072},
            {"name": "no-ctx:latest"},
        ]});
        let idx = index_ps(&ps).unwrap();
        assert_eq!(idx.get(&normalize_model_name("qwen3.6")), Some(&131_072));
        assert_eq!(idx.get(&normalize_model_name("no-ctx")), None);
        assert!(index_ps(&json!({"error": "x"})).is_none());
    }

    #[test]
    fn the_message_names_counts_not_content() {
        let m = truncation_message("qwen3.6:latest", 2_050, 4_096);
        assert!(m.contains("4096-token") && m.contains("2050"));
        assert!(!m.contains("HTTP 400"));
    }
}
