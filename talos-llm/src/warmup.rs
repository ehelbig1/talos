//! Boot-time warmup for LOCAL (Ollama) generation models.
//!
//! # Why
//!
//! Ollama lazily loads a model into VRAM on first use and unloads it
//! after `keep_alive` expires. The live LLM nodes pin their model with
//! `keep_alive: "3h"` — but that residency dies with the container. So
//! after every deploy or host restart, the *first* workflow to reach an
//! LLM node pays the cold model load plus first-inference warm-up: tens
//! of seconds on a CPU/consumer-GPU host.
//!
//! That cost landed on a user-visible run twice in production. The
//! flagship `pa-chief-of-staff` briefing failed its scheduled run on two
//! consecutive days, both times minutes after a stack restart: its
//! `synthesize` node (qwen3.6) averages ~61 s warm and had been trending
//! up, and the cold-load surcharge pushed the workflow past its 180 s
//! execution cap.
//!
//! The embedding provider already gets a boot warmup for exactly this
//! reason (`talos_memory::embedding::warmup`). Generation did not. This
//! module closes that gap: it moves the cold-start off the first real
//! run and onto boot, where nobody is waiting.
//!
//! # Security posture
//!
//! * **Local provider only.** The endpoint is always the process's
//!   configured [`OllamaClient`] — i.e. `OLLAMA_URL`. Nothing from
//!   `graph_json` ever contributes to a URL. External providers
//!   (Anthropic / OpenAI / Gemini) are never warmed: a data-less request
//!   is still an unannounced egress from a host that may be running
//!   tier-1 actors precisely to avoid one.
//! * **Static prompt.** The request body carries the constant
//!   [`WARMUP_PROMPT`] and `num_predict: 1`. No user data, no workflow
//!   content, no memory.
//! * **Validated model / keep-alive strings.** `MODEL` and
//!   `PROVIDER_OPTIONS.keep_alive` come out of `graph_json`, which is
//!   operator- and LLM-authored. Both are charset- and length-checked
//!   before they reach a request body or a log line
//!   ([`is_safe_model_name`], [`sanitize_keep_alive`]); anything else is
//!   dropped. They are body fields, never URL components.
//! * **Bounded.** At most [`MAX_WARMUP_MODELS`] distinct models, run
//!   sequentially (a parallel warmup would thrash a single-GPU host and
//!   make the cold start *worse*), each under its own deadline.
//! * **Fail-soft.** Every outcome is a log line. The task is spawned;
//!   boot never waits on it and never fails because of it.
//! * **No config values beyond MODEL / PROVIDER / keep_alive are read**,
//!   and none are logged beyond the model name itself.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::OllamaClient;

/// The one and only prompt a warmup ever sends. A constant, so no code
/// path can substitute user or workflow content.
pub const WARMUP_PROMPT: &str = "ok";

/// Hard ceiling on distinct models warmed per boot.
///
/// Each load occupies VRAM and takes tens of seconds; warming the long
/// tail of rarely-used models would evict the ones that matter and
/// stretch the warmup window past the first scheduled run it exists to
/// protect. Three covers the flagship set.
pub const MAX_WARMUP_MODELS: usize = 3;

/// Per-model wall-clock budget. A model that has not answered a
/// one-token prompt in two minutes is not going to help the next
/// scheduled run either; move on to the next one.
///
/// Enforced TWICE, deliberately: as a per-request `reqwest` timeout
/// inside [`OllamaClient::warm_model`](crate::OllamaClient::warm_model)
/// — which is what actually bounds a socket that accepts the connection
/// and then never answers — and again by the task-level
/// [`tokio::time::timeout`] in [`run_boot_warmup`], which covers
/// anything outside the HTTP call. The request-level override is load
/// bearing: without it the client-wide 60 s Ollama timeout would cap
/// every warmup at HALF this budget, giving up on a cold load right in
/// the window this module exists to absorb.
pub const WARMUP_MODEL_DEADLINE: Duration = Duration::from_secs(120);

/// Slack between the request-level deadline and the task-level backstop.
///
/// Two timers set to the identical instant make it a coin flip which one
/// fires, so the log line for a stuck model would alternate between
/// `..._model_failed` and `..._model_deadline` for one condition. The
/// grace makes the request timeout the expected reporter (it names the
/// transport error) and leaves the task timeout a true backstop.
const WARMUP_DEADLINE_GRACE: Duration = Duration::from_secs(5);

/// Residency hint used when a node references a model without naming
/// its own `keep_alive` — matches the value the live LLM/classifier
/// nodes use, so warmup residency lines up with run-time residency
/// instead of decaying at Ollama's 5-minute default.
pub const DEFAULT_KEEP_ALIVE: &str = "3h";

/// Defensive bounds on the two `graph_json`-sourced strings.
const MAX_MODEL_NAME_CHARS: usize = 128;
const MAX_KEEP_ALIVE_CHARS: usize = 16;

/// One model to warm, with the residency hint its referencing nodes use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmupTarget {
    /// Ollama model name exactly as the graph spells it, e.g.
    /// `qwen3.6:latest`. Already validated by [`is_safe_model_name`].
    pub model: String,
    /// `keep_alive` to send with the warmup request.
    pub keep_alive: String,
    /// How many enabled-workflow nodes referenced this model. Logged so
    /// an operator can see why a model made the cut.
    pub references: usize,
}

/// Ollama model names are `[namespace/]name[:tag]`, sometimes with a
/// registry host (`hf.co/org/repo:Q4_K_M`). Everything outside this
/// charset is either a typo or an attempt to smuggle structure into a
/// field we then log — reject rather than sanitize.
fn is_safe_model_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= MAX_MODEL_NAME_CHARS
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '@'))
        // `://` and `..` are inside the charset but are never valid in an
        // Ollama model reference — they only appear when someone is
        // trying to make the string read as a URL or a path. The endpoint
        // is pinned to the configured client regardless, so this is
        // hygiene rather than the SSRF control, but a model name that
        // looks like a URL in a log line is its own confusion.
        && !s.contains("://")
        && !s.contains("..")
        && !s.starts_with('/')
}

/// Ollama accepts a Go duration (`3h`, `30m`, `90s`) or a bare number of
/// seconds (`-1` pins forever, `0` unloads immediately). Anything else
/// falls back to the default rather than being forwarded.
fn sanitize_keep_alive(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.chars().count() > MAX_KEEP_ALIVE_CHARS {
        return None;
    }
    let ok = t
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, 'h' | 'm' | 's' | '.' | '-'));
    // Must contain at least one digit — bare "h" or "-" is not a duration.
    if ok && t.chars().any(|c| c.is_ascii_digit()) {
        Some(t.to_string())
    } else {
        None
    }
}

/// The per-node config map in `graph_json`.
///
/// Canonical form puts the config directly under `data`; several MCP
/// write paths emit a nested `data.config` instead. Check both so the
/// scan doesn't silently miss half the fleet.
fn node_config(node: &serde_json::Value) -> Option<&serde_json::Map<String, serde_json::Value>> {
    let data = node.get("data")?;
    if let Some(nested) = data.get("config").and_then(|c| c.as_object()) {
        return Some(nested);
    }
    data.as_object()
}

/// Pull `PROVIDER_OPTIONS.keep_alive` off a node config.
///
/// `PROVIDER_OPTIONS` is schema'd as an object, but module templates
/// also hand the provider a raw JSON *string*, and both shapes turn up
/// in stored graphs — accept either.
fn node_keep_alive(cfg: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let opts = cfg.get("PROVIDER_OPTIONS")?;
    let raw = match opts {
        serde_json::Value::Object(map) => map.get("keep_alive")?.as_str()?.to_string(),
        serde_json::Value::String(s) => serde_json::from_str::<serde_json::Value>(s)
            .ok()?
            .get("keep_alive")?
            .as_str()?
            .to_string(),
        _ => return None,
    };
    sanitize_keep_alive(&raw)
}

/// Per-model tally accumulated across every scanned graph.
#[derive(Default)]
struct ModelTally {
    references: usize,
    /// `keep_alive` value -> how many nodes asked for it. The most
    /// common wins, ties broken lexicographically, so the chosen hint is
    /// deterministic across boots rather than dependent on DB row order.
    keep_alive_votes: HashMap<String, usize>,
}

/// Scan enabled workflows' `graph_json` documents and pick the models
/// worth warming.
///
/// Pure — no I/O, no clock, no env — so the selection contract (ollama
/// only, distinct, capped, most-referenced first) is directly testable.
///
/// Malformed graphs are skipped, not fatal: this runs at boot and one
/// bad row must not cost the fleet its warmup.
pub fn select_warmup_targets(graph_jsons: &[String]) -> Vec<WarmupTarget> {
    let mut tallies: HashMap<String, ModelTally> = HashMap::new();

    for raw in graph_jsons {
        let Ok(graph) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) else {
            continue;
        };
        for node in nodes {
            let Some(cfg) = node_config(node) else {
                continue;
            };
            // SECURITY: local provider only, and only when the graph says
            // so EXPLICITLY. An absent PROVIDER defaults to anthropic in
            // the llm-inference template, so "unknown" must not be
            // treated as local.
            let is_ollama = cfg
                .get("PROVIDER")
                .and_then(|v| v.as_str())
                .map(|p| p.trim().eq_ignore_ascii_case("ollama"))
                .unwrap_or(false);
            if !is_ollama {
                continue;
            }
            // No MODEL means the module falls back to its own built-in
            // default; don't guess which one — warming the wrong model is
            // pure cost.
            let Some(model) = cfg.get("MODEL").and_then(|v| v.as_str()) else {
                continue;
            };
            let model = model.trim();
            if !is_safe_model_name(model) {
                tracing::warn!(
                    target: "talos_llm",
                    event_kind = "llm_warmup_model_name_rejected",
                    model_len = model.chars().count(),
                    "Skipping LLM boot warmup for a model name outside the permitted charset"
                );
                continue;
            }
            let entry = tallies.entry(model.to_string()).or_default();
            entry.references += 1;
            if let Some(ka) = node_keep_alive(cfg) {
                *entry.keep_alive_votes.entry(ka).or_default() += 1;
            }
        }
    }

    let mut targets: Vec<WarmupTarget> = tallies
        .into_iter()
        .map(|(model, tally)| {
            let keep_alive = tally
                .keep_alive_votes
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
                .map(|(k, _)| k)
                .unwrap_or_else(|| DEFAULT_KEEP_ALIVE.to_string());
            WarmupTarget {
                model,
                keep_alive,
                references: tally.references,
            }
        })
        .collect();

    // Most-referenced first; ties broken by model name so the capped set
    // is stable across boots.
    targets.sort_by(|a, b| {
        b.references
            .cmp(&a.references)
            .then_with(|| a.model.cmp(&b.model))
    });
    targets.truncate(MAX_WARMUP_MODELS);
    targets
}

/// Warm each target sequentially against the process's configured local
/// Ollama endpoint.
///
/// Intended to be `tokio::spawn`ed after the boot reachability probe
/// succeeds. Never panics, never returns an error, never blocks boot.
///
/// Sequential by design: concurrent loads on a single-GPU host contend
/// for VRAM and can evict each other, turning a warmup into a slowdown.
pub async fn run_boot_warmup(client: Arc<OllamaClient>, targets: Vec<WarmupTarget>) {
    if targets.is_empty() {
        tracing::info!(
            target: "talos_llm",
            event_kind = "llm_boot_warmup_skipped",
            "LLM boot warmup found no enabled workflow referencing a local (ollama) model"
        );
        return;
    }

    tracing::info!(
        target: "talos_llm",
        event_kind = "llm_boot_warmup_started",
        models = targets.len(),
        "Warming local generation models so the first scheduled run does not pay the cold load"
    );

    for target in targets {
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(
            WARMUP_MODEL_DEADLINE + WARMUP_DEADLINE_GRACE,
            client.warm_model(&target.model, &target.keep_alive),
        )
        .await;
        let duration_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(Ok(())) => tracing::info!(
                target: "talos_llm",
                event_kind = "llm_boot_warmup_model_ok",
                model = %target.model,
                keep_alive = %target.keep_alive,
                references = target.references,
                duration_ms,
                "LLM boot warmup OK — model loaded"
            ),
            Ok(Err(e)) => tracing::warn!(
                target: "talos_llm",
                event_kind = "llm_boot_warmup_model_failed",
                model = %target.model,
                references = target.references,
                duration_ms,
                error = %e,
                "LLM boot warmup failed — the first run using this model pays the cold load"
            ),
            Err(_) => tracing::warn!(
                target: "talos_llm",
                event_kind = "llm_boot_warmup_model_deadline",
                model = %target.model,
                references = target.references,
                duration_ms,
                deadline_secs = (WARMUP_MODEL_DEADLINE + WARMUP_DEADLINE_GRACE).as_secs(),
                "LLM boot warmup exceeded its per-model deadline — moving on"
            ),
        }
    }

    tracing::info!(
        target: "talos_llm",
        event_kind = "llm_boot_warmup_finished",
        "LLM boot warmup finished"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph(nodes: serde_json::Value) -> String {
        json!({ "nodes": nodes, "edges": [] }).to_string()
    }

    fn ollama_node(model: &str) -> serde_json::Value {
        json!({ "id": model, "data": { "PROVIDER": "ollama", "MODEL": model } })
    }

    #[test]
    fn extracts_distinct_ollama_models() {
        let g = graph(json!([
            ollama_node("qwen3.6:latest"),
            ollama_node("mistral")
        ]));
        let targets = select_warmup_targets(&[g]);
        let mut names: Vec<&str> = targets.iter().map(|t| t.model.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["mistral", "qwen3.6:latest"]);
    }

    #[test]
    fn deduplicates_and_counts_references_across_graphs() {
        let a = graph(json!([ollama_node("qwen3.6:latest")]));
        let b = graph(json!([
            ollama_node("qwen3.6:latest"),
            ollama_node("qwen3.6:latest")
        ]));
        let targets = select_warmup_targets(&[a, b]);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].model, "qwen3.6:latest");
        assert_eq!(targets[0].references, 3);
    }

    #[test]
    fn skips_every_external_provider() {
        // MUTATION GUARD: if warmup ever reaches an external provider,
        // this fails. Warming Anthropic/OpenAI/Gemini would be an
        // unannounced egress from a host that may be deliberately
        // tier-1.
        let g = graph(json!([
            json!({ "id": "1", "data": { "PROVIDER": "anthropic", "MODEL": "claude-sonnet-4-6" } }),
            json!({ "id": "2", "data": { "PROVIDER": "openai", "MODEL": "gpt-4o" } }),
            json!({ "id": "3", "data": { "PROVIDER": "gemini", "MODEL": "gemini-2.0" } }),
        ]));
        assert!(select_warmup_targets(&[g]).is_empty());
    }

    #[test]
    fn absent_provider_is_not_treated_as_local() {
        // The llm-inference template defaults an absent PROVIDER to
        // anthropic, so "unknown" must fail closed to external.
        let g = graph(json!([
            json!({ "id": "1", "data": { "MODEL": "qwen3.6" } })
        ]));
        assert!(select_warmup_targets(&[g]).is_empty());
    }

    #[test]
    fn provider_match_is_case_insensitive_and_trimmed() {
        let g = graph(json!([
            json!({ "id": "1", "data": { "PROVIDER": " Ollama ", "MODEL": "qwen3.6" } }),
        ]));
        assert_eq!(select_warmup_targets(&[g]).len(), 1);
    }

    #[test]
    fn reads_the_nested_data_config_shape_too() {
        let g = graph(json!([
            json!({ "id": "1", "data": { "label": "x", "config": { "PROVIDER": "ollama", "MODEL": "qwen3.6" } } }),
        ]));
        assert_eq!(select_warmup_targets(&[g])[0].model, "qwen3.6");
    }

    #[test]
    fn model_list_is_capped_at_the_documented_ceiling() {
        // MUTATION GUARD: removing the cap fails here.
        let nodes: Vec<serde_json::Value> = (0..10)
            .flat_map(|i| {
                // Give each model a distinct reference count so ordering
                // is unambiguous: model i gets (10 - i) references.
                let m = format!("model-{i:02}");
                (0..(10 - i)).map(move |_| ollama_node(&m))
            })
            .collect();
        let targets = select_warmup_targets(&[graph(json!(nodes))]);
        assert_eq!(targets.len(), MAX_WARMUP_MODELS);
        assert_eq!(
            targets.iter().map(|t| t.model.as_str()).collect::<Vec<_>>(),
            vec!["model-00", "model-01", "model-02"],
            "most-referenced models must win the capped slots"
        );
    }

    #[test]
    fn ordering_ties_break_on_model_name_for_stability() {
        let g = graph(json!([ollama_node("zeta"), ollama_node("alpha")]));
        let targets = select_warmup_targets(&[g]);
        assert_eq!(targets[0].model, "alpha");
    }

    #[test]
    fn keep_alive_is_read_from_provider_options() {
        let g = graph(json!([json!({
            "id": "1",
            "data": {
                "PROVIDER": "ollama",
                "MODEL": "qwen3.6",
                "PROVIDER_OPTIONS": { "think": false, "keep_alive": "30m" }
            }
        })]));
        assert_eq!(select_warmup_targets(&[g])[0].keep_alive, "30m");
    }

    #[test]
    fn keep_alive_is_read_from_a_stringified_provider_options() {
        let g = graph(json!([json!({
            "id": "1",
            "data": {
                "PROVIDER": "ollama",
                "MODEL": "qwen3.6",
                "PROVIDER_OPTIONS": r#"{"think":false,"keep_alive":"3h"}"#
            }
        })]));
        assert_eq!(select_warmup_targets(&[g])[0].keep_alive, "3h");
    }

    #[test]
    fn keep_alive_defaults_to_the_live_node_shape_when_absent() {
        let g = graph(json!([ollama_node("qwen3.6")]));
        assert_eq!(
            select_warmup_targets(&[g])[0].keep_alive,
            DEFAULT_KEEP_ALIVE
        );
    }

    #[test]
    fn most_common_keep_alive_wins_deterministically() {
        let g = graph(json!([
            json!({ "id":"1","data":{ "PROVIDER":"ollama","MODEL":"m","PROVIDER_OPTIONS":{"keep_alive":"30m"} } }),
            json!({ "id":"2","data":{ "PROVIDER":"ollama","MODEL":"m","PROVIDER_OPTIONS":{"keep_alive":"3h"} } }),
            json!({ "id":"3","data":{ "PROVIDER":"ollama","MODEL":"m","PROVIDER_OPTIONS":{"keep_alive":"3h"} } }),
        ]));
        assert_eq!(select_warmup_targets(&[g])[0].keep_alive, "3h");
    }

    #[test]
    fn hostile_model_names_are_rejected() {
        // MUTATION GUARD for the "crafted MODEL string" class. These
        // never reach a request body OR a log line. (They could not
        // reach a URL regardless — the endpoint is always the configured
        // OllamaClient — but rejecting keeps log output structural.)
        for bad in [
            "http://evil.example/api",
            "model with spaces",
            "model\nInjected: header",
            "model\"quoted\"",
            "../../etc/passwd\0",
            "",
        ] {
            let g = graph(json!([
                json!({ "id": "1", "data": { "PROVIDER": "ollama", "MODEL": bad } }),
            ]));
            assert!(
                select_warmup_targets(&[g]).is_empty(),
                "model name {bad:?} must be rejected"
            );
        }
        let long = "a".repeat(MAX_MODEL_NAME_CHARS + 1);
        let g = graph(json!([
            json!({ "id": "1", "data": { "PROVIDER": "ollama", "MODEL": long } }),
        ]));
        assert!(select_warmup_targets(&[g]).is_empty(), "over-long name");
    }

    #[test]
    fn hostile_keep_alive_falls_back_to_the_default() {
        for bad in ["3h; rm -rf /", "\"}}injected", "forever", ""] {
            let g = graph(json!([json!({
                "id": "1",
                "data": { "PROVIDER":"ollama","MODEL":"m","PROVIDER_OPTIONS":{"keep_alive": bad } }
            })]));
            assert_eq!(
                select_warmup_targets(&[g])[0].keep_alive,
                DEFAULT_KEEP_ALIVE,
                "keep_alive {bad:?} must not be forwarded"
            );
        }
    }

    #[test]
    fn malformed_graphs_are_skipped_not_fatal() {
        let good = graph(json!([ollama_node("qwen3.6")]));
        let inputs = vec![
            "not json at all".to_string(),
            "{}".to_string(),
            json!({ "nodes": "not an array" }).to_string(),
            json!({ "nodes": [ {"id":"1"}, {"id":"2","data": 7} ] }).to_string(),
            good,
        ];
        assert_eq!(select_warmup_targets(&inputs)[0].model, "qwen3.6");
    }

    #[test]
    fn empty_input_yields_no_targets() {
        assert!(select_warmup_targets(&[]).is_empty());
    }

    #[tokio::test]
    async fn warmup_against_an_unreachable_provider_is_fail_soft() {
        // Provider-down lane: the task must return normally (no panic,
        // no error propagation) so a spawned boot warmup can never
        // affect the controller's startup.
        //
        // Port 1 on loopback refuses instantly — no network egress, no
        // DNS, and bounded well under the per-model deadline.
        let client = Arc::new(OllamaClient::new("http://127.0.0.1:1".to_string()));
        let targets = vec![
            WarmupTarget {
                model: "qwen3.6:latest".to_string(),
                keep_alive: "3h".to_string(),
                references: 2,
            },
            WarmupTarget {
                model: "mistral".to_string(),
                keep_alive: "3h".to_string(),
                references: 1,
            },
        ];
        // Completes, and completes fast — a hang here would mean the
        // deadline is not doing its job.
        let started = std::time::Instant::now();
        run_boot_warmup(client, targets).await;
        assert!(
            started.elapsed() < WARMUP_MODEL_DEADLINE,
            "unreachable provider must fail fast, not sit on the deadline"
        );
    }

    #[tokio::test]
    async fn empty_target_list_is_a_no_op() {
        let client = Arc::new(OllamaClient::new("http://127.0.0.1:1".to_string()));
        run_boot_warmup(client, vec![]).await;
    }

    #[test]
    fn the_per_model_budget_exceeds_the_client_wide_ollama_timeout() {
        // This inequality is the entire reason `warm_model` carries an
        // explicit per-request `.timeout(WARMUP_MODEL_DEADLINE)`: the
        // client-wide Ollama timeout is SHORTER than the budget this
        // module documents, so without the override a cold load gets half
        // the time it was promised — and a >60 s cold load is exactly the
        // case the warmup exists to absorb. If this constant is ever
        // lowered below the client timeout the override becomes dead code,
        // and this assertion is the note explaining why it was there.
        assert!(
            WARMUP_MODEL_DEADLINE > crate::OLLAMA_HTTP_TIMEOUT,
            "the per-request timeout override in warm_model is only \
             meaningful while the warmup budget exceeds the client-wide one"
        );
        // The task-level backstop must sit strictly after the request-level
        // deadline, or the two race and the failure log line is a coin flip.
        assert!(WARMUP_DEADLINE_GRACE > Duration::ZERO);
    }
}
