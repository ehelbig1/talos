//! Scripted [`NodeDispatcher`] — declare `(module_id → response)` up
//! front and the dispatcher returns the configured result on each
//! `dispatch` call. Used to simulate worker responses in unit tests
//! without bringing up NATS or a real wasm runtime.

use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{BoxError, DispatchJob, DispatchResult, NodeDispatcher};
use uuid::Uuid;

/// One scripted response.
#[derive(Clone, Debug)]
enum ScriptedResponse {
    Ok(JsonValue),
    Err(String),
}

/// [`NodeDispatcher`] that returns scripted responses keyed on
/// `module_id`.
///
/// When the engine calls `dispatch(job)`, the dispatcher looks up
/// `job.module_id` in its scripted map. A hit returns the configured
/// `Ok(output)` or `Err(message)`; a miss returns an error
/// identifying the missing mapping (surface-level clear failure mode
/// for tests that forgot to seed a module).
///
/// `dispatch_chain` delegates to [`NodeDispatcher::dispatch_chain`]'s
/// default body — looping over per-step `dispatch` calls — so chained
/// pipelines work with zero extra setup.
#[derive(Clone, Default)]
pub struct ScriptedDispatcher {
    responses: Arc<DashMap<Uuid, ScriptedResponse>>,
    dispatch_count: Arc<DashMap<Uuid, usize>>,
}

impl ScriptedDispatcher {
    /// Build an empty dispatcher. Every `dispatch` call will error
    /// until at least one response is scripted via
    /// [`with_response`](Self::with_response) or
    /// [`with_error`](Self::with_error).
    pub fn new() -> Self {
        Self::default()
    }

    /// Script a successful response for `module_id`.
    pub fn with_response(self, module_id: Uuid, output: JsonValue) -> Self {
        self.responses
            .insert(module_id, ScriptedResponse::Ok(output));
        self
    }

    /// Script an error response for `module_id`. The engine's retry
    /// loop will treat this like a transport failure.
    pub fn with_error(self, module_id: Uuid, error: impl Into<String>) -> Self {
        self.responses
            .insert(module_id, ScriptedResponse::Err(error.into()));
        self
    }

    /// How many times `dispatch` has been called for `module_id`.
    /// Use in tests that assert on retry behavior.
    pub fn dispatch_count(&self, module_id: Uuid) -> usize {
        self.dispatch_count.get(&module_id).map_or(0, |e| *e)
    }

    /// Total dispatch count across all modules.
    pub fn total_dispatches(&self) -> usize {
        self.dispatch_count.iter().map(|e| *e.value()).sum()
    }
}

impl std::fmt::Debug for ScriptedDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptedDispatcher")
            .field("scripted_modules", &self.responses.len())
            .field("total_dispatches", &self.total_dispatches())
            .finish()
    }
}

#[async_trait]
impl NodeDispatcher for ScriptedDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        // Record the attempt BEFORE looking up the response, so the
        // count reflects tries even on misses.
        *self.dispatch_count.entry(job.module_id).or_insert(0) += 1;

        let Some(entry) = self.responses.get(&job.module_id) else {
            let e: BoxError = format!(
                "ScriptedDispatcher: no response scripted for module {}",
                job.module_id
            )
            .into();
            return Err(e);
        };
        match entry.value() {
            ScriptedResponse::Ok(v) => Ok(DispatchResult { output: v.clone() }),
            ScriptedResponse::Err(msg) => {
                let e: BoxError = msg.clone().into();
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn stub_job(module_id: Uuid) -> DispatchJob {
        DispatchJob {
            execution_id: Uuid::nil(),
            node_id: Uuid::nil(),
            module_id,
            job_id: None,
            user_id: None,
            actor_id: None,
            module_uri: "test".into(),
            wasm_bytes: None,
            expected_wasm_hash: None,
            capability_world: None,
            integration_name: None,
            input_payload: JsonValue::Null,
            timeout: Duration::from_secs(30),
            max_fuel: 1_000_000,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            encrypted_secrets_ciphertext: vec![],
            encrypted_secrets_nonce: vec![],
            plaintext_secrets: None,
            secret_paths: Vec::new(),
            priority: 100,
            dry_run: false,
            max_llm_tier: talos_workflow_engine_core::LlmTier::default(),
            max_write_ceiling: talos_workflow_engine_core::WriteCeiling::default(),
            egress_scope: None,
            max_retries: 0,
            backoff_ms: 0,
            retry_condition: None,
            retry_delay_expr: None,
            emit_retry_events: false,
        }
    }

    #[tokio::test]
    async fn scripted_response_returned() {
        let id = Uuid::new_v4();
        let d = ScriptedDispatcher::new().with_response(id, serde_json::json!({ "result": 42 }));
        let out = d.dispatch(stub_job(id)).await.expect("scripted");
        assert_eq!(out.output, serde_json::json!({ "result": 42 }));
        assert_eq!(d.dispatch_count(id), 1);
    }

    #[tokio::test]
    async fn scripted_error_returned() {
        let id = Uuid::new_v4();
        let d = ScriptedDispatcher::new().with_error(id, "boom");
        let err = d.dispatch(stub_job(id)).await.expect_err("scripted err");
        assert!(err.to_string().contains("boom"));
        assert_eq!(d.dispatch_count(id), 1);
    }

    #[tokio::test]
    async fn unscripted_module_errors_loudly() {
        let id = Uuid::new_v4();
        let d = ScriptedDispatcher::new();
        let err = d.dispatch(stub_job(id)).await.expect_err("missing");
        assert!(err.to_string().contains("no response scripted"));
        // Miss still counts as an attempt.
        assert_eq!(d.dispatch_count(id), 1);
    }
}
