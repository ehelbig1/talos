//! A pipeline step is given the `vault://` references its config names that
//! its module's grant admits, and no others (security review 2026-10-14,
//! G-27).
//!
//! The chain path passed an empty grant to the secrets pipeline. Once a
//! config reference is filtered through the module's grant (the matcher the
//! worker applies at substitution), an empty grant would drop every step's
//! credential; and without the filter a reference outside the grant was
//! resolved and sealed into a job that could not use it.
//!
//! Driven through `run_with_transport`, the entry point that dispatches a
//! linear chain as one pipeline, with a resolver that records what it is
//! asked for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, NodeDispatcher, SecretsResolver, StepStatus, WasmModuleArtifact,
    WorkerSharedKey,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

#[derive(Default)]
struct RecordingResolver {
    paths: Mutex<Vec<String>>,
}

#[async_trait]
impl SecretsResolver for RecordingResolver {
    async fn resolve_module_secrets(
        &self,
        _node_id: Uuid,
        _user_id: Option<Uuid>,
    ) -> Result<talos_workflow_engine_core::SecretMap, BoxError> {
        Ok(HashMap::new())
    }

    async fn resolve_by_paths(
        &self,
        paths: &[String],
        _user_id: Option<Uuid>,
    ) -> Result<talos_workflow_engine_core::SecretMap, BoxError> {
        self.paths.lock().unwrap().extend(paths.iter().cloned());
        Ok(paths
            .iter()
            .map(|p| (p.clone(), zeroize::Zeroizing::new("value".to_string())))
            .collect())
    }
}

/// Counts chain calls so the test cannot pass on a graph that never chained.
#[derive(Default)]
struct ChainDispatcher {
    chain_calls: Mutex<usize>,
}

#[async_trait]
impl NodeDispatcher for ChainDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult {
            output: json!({"output": "ok"}),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        *self.chain_calls.lock().unwrap() += 1;
        Ok(ChainDispatchResult {
            steps: request
                .steps
                .iter()
                .map(|j| ChainStepResult {
                    module_id: j.module_id,
                    status: StepStatus::Success,
                    output: json!({"output": "ok"}),
                    error: None,
                    execution_time_ms: 0,
                })
                .collect(),
            final_output: json!({"output": "ok"}),
            overall_status: StepStatus::Success,
        })
    }
}

/// The chain path reads a step's config from its module artifact.
fn artifact(id: Uuid, config: serde_json::Value) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "http-node".into(),
        allowed_hosts: vec!["api.example.com".into()],
        allowed_methods: vec!["GET".into()],
        allowed_secrets: vec!["cfg/*".into()],
        requires_approval_for: vec![],
        integration_name: None,
        config: Some(config),
    }
}

#[tokio::test]
async fn a_pipeline_step_is_given_only_the_config_references_its_grant_admits() {
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let config = json!({
        "AUTH": "Bearer vault://cfg/granted",
        "OTHER": "Bearer vault://other/not_granted",
    });
    let graph = WorkflowGraphBuilder::new()
        .add_module(ids[0].to_string(), ids[0], None)
        .add_module(ids[1].to_string(), ids[1], None)
        .add_module(ids[2].to_string(), ids[2], None)
        .edge(ids[0].to_string(), ids[1].to_string())
        .edge(ids[1].to_string(), ids[2].to_string())
        .build()
        .expect("graph builds");

    let resolver = Arc::new(RecordingResolver::default());
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_secrets_resolver(resolver.clone());
    let mut fetcher = InMemoryModuleFetcher::new();
    for id in ids {
        fetcher = fetcher.with_module(id, artifact(id, config.clone()));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(ChainDispatcher::default());
    engine
        .run_with_transport(
            dispatcher.clone(),
            Some(WorkerSharedKey::new(vec![7u8; 32])),
            Uuid::new_v4(),
        )
        .await
        .expect("run");

    assert_eq!(
        *dispatcher.chain_calls.lock().unwrap(),
        1,
        "the graph must run as one pipeline for this test to mean anything"
    );
    let paths = resolver.paths.lock().unwrap().clone();
    let asks = |path: &str| paths.iter().filter(|p| p.as_str() == path).count();
    assert_eq!(
        asks("cfg/granted"),
        3,
        "each step must be given the reference its grant admits: {paths:?}"
    );
    assert_eq!(
        asks("other/not_granted"),
        0,
        "a step was given a reference outside its grant: {paths:?}"
    );
}
