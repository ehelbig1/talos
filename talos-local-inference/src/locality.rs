//! Is an Ollama model actually LOCAL?
//!
//! Talos treats every Ollama call as local inference: the worker's tier-1 gate
//! (`decide_llm_tier_access`) lets a `max_llm_tier = tier1` actor call Ollama
//! with no further check, and the controller's `OllamaClient` is the path every
//! "local" controller job takes (consolidation, reflection, graph-RAG
//! extraction, evaluation, the teacher audit, `local_llm_complete`). Neither
//! was true of an Ollama CLOUD model: Ollama serves a model such as
//! `glm-5.3-flash:cloud` by forwarding the prompt to `https://ollama.com`, so a
//! tier-1 actor pointed at one sent its data off the host through the one
//! provider the tier-1 gate trusted. Measured on the reference host
//! 2026-09-30: Ollama 0.35.0 with one such model pulled, zero nodes using it.
//!
//! A model is REMOTE when either
//! * its tag is `cloud` or ends in `-cloud` (Ollama's naming, e.g.
//!   `glm-5.3-flash:cloud`, `gpt-oss:120b-cloud`) — decided without a network
//!   call; or
//! * Ollama's `/api/tags` lists it with a non-empty `remote_host` — the
//!   authoritative signal, which also covers an alias made with `ollama cp`
//!   whose name no longer says "cloud".
//!
//! A model ABSENT from the listing is [`ModelLocality::Unlisted`], not local:
//! the check can vouch only for what it can see, and Ollama answers an unknown
//! name with 404 anyway, so refusing it costs a legitimate caller nothing.
//! A listing that cannot be read is an `Err` — a gate that cannot read its
//! rule refuses.
//!
//! The listing is cached per base URL for [`TAGS_CACHE_TTL`], so a busy
//! process asks Ollama at most once per TTL; the lock is held across the fetch
//! so concurrent callers share one request.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long one `/api/tags` answer is trusted. Short, because an operator who
/// pulls a model expects the next call to see it.
pub const TAGS_CACHE_TTL: Duration = Duration::from_secs(30);

/// Deadline for the `/api/tags` request. The listing is local and small; a
/// backend that cannot answer it in 5 s will not serve a chat either.
pub const TAGS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// What the check found for one model name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelLocality {
    /// Listed by the local Ollama with no `remote_host`: weights on this host.
    Local,
    /// Served elsewhere. `host` is Ollama's `remote_host`, or
    /// [`CLOUD_BY_NAME`] when the name alone decided it.
    Remote { host: String },
    /// Not in Ollama's listing, so the check cannot say where it runs.
    Unlisted,
}

impl ModelLocality {
    /// Only [`ModelLocality::Local`] may carry data that must stay on the host.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }
}

/// The `host` reported when the model's tag decided it.
pub const CLOUD_BY_NAME: &str = "ollama cloud (by model tag)";

/// The model listing could not be read. Carries a short, value-free reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalityUnreadable(pub String);

impl std::fmt::Display for LocalityUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ollama's model list could not be read: {}", self.0)
    }
}

/// The comparison form of a model name: trimmed, lower-cased, `:latest`
/// appended when there is no tag (Ollama resolves `qwen3.6` to
/// `qwen3.6:latest`). A `:` inside a registry host (`host:5000/ns/model`) is
/// not a tag separator.
#[must_use]
pub fn normalize_model_name(model: &str) -> String {
    let m = model.trim().to_ascii_lowercase();
    match m.rsplit_once(':') {
        Some((_, tag)) if !tag.contains('/') => m,
        _ => format!("{m}:latest"),
    }
}

/// True when the model's tag marks it as an Ollama cloud model.
#[must_use]
pub fn is_cloud_model_name(model: &str) -> bool {
    let m = normalize_model_name(model);
    let tag = m.rsplit_once(':').map(|(_, t)| t).unwrap_or("");
    tag == "cloud" || tag.ends_with("-cloud")
}

/// `normalized name -> remote_host` (`None` = local) from an `/api/tags` body.
/// Entries without a usable name are skipped; both `name` and `model` are
/// indexed because Ollama reports both.
fn index_tags(tags: &serde_json::Value) -> HashMap<String, Option<String>> {
    let mut out = HashMap::new();
    let Some(models) = tags.get("models").and_then(|m| m.as_array()) else {
        return out;
    };
    for entry in models {
        let remote = entry
            .get("remote_host")
            .and_then(|h| h.as_str())
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string);
        for key in ["name", "model"] {
            if let Some(n) = entry.get(key).and_then(|n| n.as_str()) {
                if !n.trim().is_empty() {
                    out.insert(normalize_model_name(n), remote.clone());
                }
            }
        }
    }
    out
}

/// The pure decision over an already-read listing.
#[must_use]
pub fn locality_from_tags(tags: &serde_json::Value, model: &str) -> ModelLocality {
    decide(&index_tags(tags), model)
}

fn decide(index: &HashMap<String, Option<String>>, model: &str) -> ModelLocality {
    if is_cloud_model_name(model) {
        return ModelLocality::Remote {
            host: CLOUD_BY_NAME.to_string(),
        };
    }
    match index.get(&normalize_model_name(model)) {
        Some(Some(host)) => ModelLocality::Remote { host: host.clone() },
        Some(None) => ModelLocality::Local,
        None => ModelLocality::Unlisted,
    }
}

type Index = HashMap<String, Option<String>>;

fn cache() -> &'static tokio::sync::Mutex<HashMap<String, (Instant, Index)>> {
    static CACHE: OnceLock<tokio::sync::Mutex<HashMap<String, (Instant, Index)>>> = OnceLock::new();
    CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

async fn fetch_index(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<Index, LocalityUnreadable> {
    let resp = client
        .get(format!("{}/api/tags", base_url.trim_end_matches('/')))
        .timeout(TAGS_FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            LocalityUnreadable(if e.is_timeout() {
                "request timed out".to_string()
            } else {
                "request failed".to_string()
            })
        })?;
    if !resp.status().is_success() {
        // "status", not "HTTP": `OllamaClient` callers retry on an error
        // containing `HTTP 400`, and this is not that error.
        return Err(LocalityUnreadable(format!(
            "status {}",
            resp.status().as_u16()
        )));
    }
    let body: serde_json::Value = talos_http_body::read_json_capped(resp)
        .await
        .map_err(|_| LocalityUnreadable("response was not a readable JSON body".to_string()))?;
    if body.get("models").and_then(|m| m.as_array()).is_none() {
        return Err(LocalityUnreadable(
            "response has no `models` list".to_string(),
        ));
    }
    Ok(index_tags(&body))
}

/// Where `model` runs, per the Ollama at `base_url`.
///
/// A cloud tag answers without a request. Otherwise the listing is read (at
/// most once per [`TAGS_CACHE_TTL`] per base URL, plus once more when a name
/// is missing from a cached listing) and the model looked up. A failed read is
/// never cached, so the next call retries it.
pub async fn model_locality(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
) -> Result<ModelLocality, LocalityUnreadable> {
    if is_cloud_model_name(model) {
        return Ok(decide(&Index::new(), model));
    }
    let mut guard = cache().lock().await;
    if let Some((at, index)) = guard.get(base_url) {
        if at.elapsed() < TAGS_CACHE_TTL {
            let cached = decide(index, model);
            // A miss against a cached listing may be a model pulled since it
            // was read; only a miss against a FRESH read is an answer.
            if cached != ModelLocality::Unlisted {
                return Ok(cached);
            }
        }
    }
    let index = fetch_index(client, base_url).await?;
    let answer = decide(&index, model);
    guard.insert(base_url.to_string(), (Instant::now(), index));
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The shape Ollama 0.35.0 returned on the reference host, trimmed.
    fn tags() -> serde_json::Value {
        json!({"models": [
            {"name": "qwen3.6:latest", "model": "qwen3.6:latest", "size": 23_900_000_000u64},
            {"name": "glm-5.3-flash:cloud", "model": "glm-5.3-flash:cloud",
             "remote_model": "glm-5.3-flash", "remote_host": "https://ollama.com", "size": 317},
            {"name": "my-alias:latest", "model": "my-alias:latest",
             "remote_host": "https://ollama.com"},
            {"name": "blank-host:latest", "remote_host": ""},
        ]})
    }

    #[test]
    fn names_are_compared_the_way_ollama_resolves_them() {
        assert_eq!(normalize_model_name("qwen3.6"), "qwen3.6:latest");
        assert_eq!(normalize_model_name(" Qwen3.6:Latest "), "qwen3.6:latest");
        assert_eq!(
            normalize_model_name("host:5000/ns/model"),
            "host:5000/ns/model:latest"
        );
        assert_eq!(
            normalize_model_name("host:5000/ns/model:7b"),
            "host:5000/ns/model:7b"
        );
    }

    #[test]
    fn a_cloud_tag_is_remote_by_name() {
        for name in [
            "glm-5.3-flash:cloud",
            "gpt-oss:120b-cloud",
            " GPT-OSS:120B-CLOUD ",
            "registry.ollama.ai/library/glm-5.3-flash:cloud",
        ] {
            assert!(is_cloud_model_name(name), "{name}");
        }
        for name in [
            "qwen3.6",
            "qwen3.6:latest",
            "cloudy:7b",
            "cloud",
            "x:cloudy",
            "cloud-model:7b",
        ] {
            assert!(!is_cloud_model_name(name), "{name}");
        }
    }

    #[test]
    fn the_listing_decides_everything_else() {
        let t = tags();
        assert_eq!(locality_from_tags(&t, "qwen3.6"), ModelLocality::Local);
        assert_eq!(
            locality_from_tags(&t, "qwen3.6:latest"),
            ModelLocality::Local
        );
        // An alias that does not say "cloud" is caught by `remote_host`.
        assert_eq!(
            locality_from_tags(&t, "my-alias"),
            ModelLocality::Remote {
                host: "https://ollama.com".into()
            }
        );
        // The cloud tag decides even with an empty listing.
        assert!(matches!(
            locality_from_tags(&json!({"models": []}), "glm-5.3-flash:cloud"),
            ModelLocality::Remote { .. }
        ));
        // Not listed: the check cannot vouch for it.
        assert_eq!(
            locality_from_tags(&t, "qwen2.5:7b"),
            ModelLocality::Unlisted
        );
        // An empty `remote_host` is not a remote host.
        assert_eq!(locality_from_tags(&t, "blank-host"), ModelLocality::Local);
        assert!(ModelLocality::Local.is_local());
        assert!(!ModelLocality::Unlisted.is_local());
    }
}
