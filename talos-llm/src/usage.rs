//! R2 token ledger: controller-side LLM usage recording.
//!
//! Worker-side LLM calls ride the signed `JobResult.llm_usage` back to the
//! controller. Controller-side calls (code generation, workflow scaffolding,
//! config suggestions, graph-RAG extraction, Ollama completions) never touch
//! a worker — their provider-reported token usage is surfaced through the
//! global sink defined here, mirroring the `talos_ml::DISTILL_CONTEXT`
//! OnceLock pattern: `main.rs` installs a recorder at boot (holding the DB
//! pool via `ActorRepository`), and every response-parse site in this crate
//! calls [`record`].
//!
//! Attribution: [`LlmClient`](crate::LlmClient) is a shared, identity-free
//! client, so the requesting user travels via a tokio **task-local** scope
//! instead of parameter plumbing — call sites that know the user wrap their
//! call in [`scoped_user`]; unwrapped calls record with `user_id = None`
//! (platform-attributed). Never trust the sink for security decisions — it
//! is accounting, not authorization.

use std::future::Future;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

/// One controller-side LLM completion's provider-reported token usage.
#[derive(Debug, Clone)]
pub struct LlmUsageRecord {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// Requesting user when a [`scoped_user`] scope is active; `None` for
    /// platform-attributed calls (background maintenance, unwrapped sites).
    pub user_id: Option<Uuid>,
}

type UsageSink = dyn Fn(LlmUsageRecord) + Send + Sync;

/// Global sink installed once at controller boot. Unset (tests, worker-less
/// tools) means records are dropped — recording is strictly best-effort and
/// must never fail or slow the LLM call path.
static USAGE_SINK: OnceLock<Arc<UsageSink>> = OnceLock::new();

tokio::task_local! {
    static USAGE_USER: Option<Uuid>;
}

/// Install the global usage sink. Idempotent-safe: the first caller wins
/// (OnceLock), matching the `DISTILL_CONTEXT` boot-wiring pattern. The sink
/// MUST be non-blocking — spawn any DB write onto the runtime rather than
/// awaiting inline.
pub fn set_usage_sink(sink: Arc<UsageSink>) {
    let _ = USAGE_SINK.set(sink);
}

/// Run `fut` with LLM usage attributed to `user_id`. Nested scopes shadow
/// (innermost wins).
pub async fn scoped_user<F: Future>(user_id: Uuid, fut: F) -> F::Output {
    USAGE_USER.scope(Some(user_id), fut).await
}

/// Record one completion's usage into the global sink (no-op when no sink is
/// installed). Called by the response-parse sites in this crate; safe to call
/// from any task — the user scope is read via `try_with` so tasks outside a
/// [`scoped_user`] scope simply record unattributed.
pub(crate) fn record(provider: &str, model: &str, prompt_tokens: u64, completion_tokens: u64) {
    if prompt_tokens == 0 && completion_tokens == 0 {
        return;
    }
    if let Some(sink) = USAGE_SINK.get() {
        let user_id = USAGE_USER.try_with(|u| *u).ok().flatten();
        sink(LlmUsageRecord {
            provider: provider.to_string(),
            model: model.to_string(),
            prompt_tokens,
            completion_tokens,
            user_id,
        });
    }
}

/// Extract `(input_tokens, output_tokens)` from an Anthropic Messages API
/// response body and [`record`] it. Missing/malformed usage records nothing —
/// accounting must never fail the completion.
pub(crate) fn record_anthropic(model: &str, body: &serde_json::Value) {
    let usage = &body["usage"];
    let prompt = usage["input_tokens"].as_u64().unwrap_or(0);
    let completion = usage["output_tokens"].as_u64().unwrap_or(0);
    record("anthropic", model, prompt, completion);
}

/// Extract `(prompt_eval_count, eval_count)` from an Ollama native
/// `/api/chat` response body and [`record`] it.
pub(crate) fn record_ollama(model: &str, body: &serde_json::Value) {
    let prompt = body["prompt_eval_count"].as_u64().unwrap_or(0);
    let completion = body["eval_count"].as_u64().unwrap_or(0);
    record("ollama", model, prompt, completion);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // NOTE: OnceLock is process-global, so all sink-observing assertions
    // live in this ONE test (multiple tests racing to set the sink would
    // interfere). The captured vec is inspected across sub-cases serially.
    #[tokio::test]
    async fn sink_records_attribution_and_extractors() {
        let captured: Arc<Mutex<Vec<LlmUsageRecord>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = captured.clone();
        set_usage_sink(Arc::new(move |r| cap.lock().unwrap().push(r)));

        // 1. Unscoped record → user_id None.
        record("anthropic", "m1", 10, 5);
        // 2. Scoped record → user_id Some.
        let uid = Uuid::new_v4();
        scoped_user(uid, async {
            record("ollama", "m2", 7, 3);
        })
        .await;
        // 3. Zero-usage records are dropped.
        record("anthropic", "m3", 0, 0);
        // 4. Anthropic extractor pulls usage.input_tokens/output_tokens.
        record_anthropic(
            "claude-sonnet-4-6",
            &serde_json::json!({"usage": {"input_tokens": 100, "output_tokens": 42}}),
        );
        // 5. Ollama extractor pulls prompt_eval_count/eval_count.
        record_ollama(
            "qwen3:6b",
            &serde_json::json!({"prompt_eval_count": 55, "eval_count": 11}),
        );
        // 6. Malformed body → nothing recorded.
        record_anthropic("m", &serde_json::json!({"usage": "garbage"}));
        record_ollama("m", &serde_json::json!({}));

        let got = captured.lock().unwrap();
        assert_eq!(got.len(), 4, "expected exactly 4 recorded entries");
        assert_eq!(got[0].user_id, None);
        assert_eq!((got[0].prompt_tokens, got[0].completion_tokens), (10, 5));
        assert_eq!(got[1].user_id, Some(uid));
        assert_eq!(got[1].provider, "ollama");
        assert_eq!(got[2].provider, "anthropic");
        assert_eq!((got[2].prompt_tokens, got[2].completion_tokens), (100, 42));
        assert_eq!(got[3].provider, "ollama");
        assert_eq!((got[3].prompt_tokens, got[3].completion_tokens), (55, 11));
    }
}
