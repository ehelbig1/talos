//! A majority-vote key built from module output must be cut on a UTF-8
//! character boundary.
//!
//! `dispatch_ensemble` bounds each candidate's vote key at 8 KiB of its
//! serialized `result`/`output`. It cut with a byte slice, `s[..8192]`, so an
//! output whose serialized form put a multi-byte character across byte 8192
//! PANICKED — inside the detached engine task, which dies without writing a
//! terminal state, leaving the execution row `running` until the stale sweep.
//! The output is module- or LLM-authored, so any caller who can shape a
//! child's output could trigger it; an LLM writing prose with an em-dash does
//! so by accident.
//!
//! Driven through the real reactor: the vote is inline in an async method,
//! and the panic is the property.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, DispatchJob, DispatchResult,
    NodeDispatcher, SystemNodeKind, WasmModuleArtifact, WorkflowGraphStore,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

/// The vote-key cap in `dispatch_ensemble`.
const MAX_VOTE_KEY_BYTES: usize = 8_192;

fn stub_artifact(id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "stub".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

struct Fixed(JsonValue);

#[async_trait]
impl NodeDispatcher for Fixed {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult {
            output: self.0.clone(),
        })
    }
    async fn dispatch_chain(
        &self,
        _request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        Err("chains are disabled on the production entry point".into())
    }
}

struct OneGraphStore(JsonValue);

#[async_trait]
impl WorkflowGraphStore for OneGraphStore {
    async fn get_graph(
        &self,
        _id: Uuid,
        _user: Uuid,
    ) -> Result<talos_workflow_engine_core::GraphLookup, BoxError> {
        Ok(talos_workflow_engine_core::GraphLookup::Found(
            self.0.clone(),
        ))
    }
    async fn get_graphs(
        &self,
        ids: &[Uuid],
        _user: Uuid,
    ) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        Ok(ids.iter().map(|&id| (id, self.0.clone())).collect())
    }
}

#[tokio::test]
async fn a_multibyte_char_across_the_vote_key_cap_does_not_panic_the_run() {
    // The key is `result.to_string()`: a JSON string, so one leading quote,
    // then the text. `MAX_VOTE_KEY_BYTES - 2` ASCII bytes put the 3-byte
    // em-dash at bytes 8191..8194, straddling the cap.
    let text = format!(
        "{}{}",
        "a".repeat(MAX_VOTE_KEY_BYTES - 2),
        "\u{2014}".repeat(8)
    );
    let key = JsonValue::String(text.clone()).to_string();
    assert!(
        !key.is_char_boundary(MAX_VOTE_KEY_BYTES),
        "the fixture must straddle the cap"
    );

    let module = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "vote",
            SystemNodeKind::Ensemble {
                child_workflow_id: Uuid::new_v4(),
                count: 3,
                consensus: "majority_vote".into(),
                judge_workflow_id: None,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("graph builds");
    let child = WorkflowGraphBuilder::new()
        .add_module("candidate", module, None)
        .build()
        .expect("child graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module, stub_artifact(module)),
    ));
    engine.set_graph_store(Arc::new(OneGraphStore(child)));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("graph loads");

    let ctx = engine
        .run_with_trigger_input_transport(
            Arc::new(Fixed(json!({ "result": text }))),
            None,
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .expect("a vote over identical long outputs completes");

    let vote = ctx
        .results
        .values()
        .find(|v| v.get("__ensemble_method__").is_some())
        .expect("the ensemble node committed its consensus");
    assert_eq!(vote["__ensemble_method__"], json!("majority_vote"));
    assert_eq!(vote["__ensemble_size__"], json!(3));
    assert_eq!(
        vote["result"],
        json!(text),
        "the winning candidate is returned whole — only the vote KEY is capped"
    );
}
