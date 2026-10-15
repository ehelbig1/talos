//! A node that combines its inputs is held to the per-node output size cap
//! (security review 2026-10-14, G-14).
//!
//! The cap (`set_max_node_output_bytes`, default 5 MiB) was applied to a
//! MODULE's output only. A `collect` over sixteen parents each just under
//! it, or a sub-workflow whose child has several terminals, produced an
//! output many times the cap — the next node's input and part of the stored
//! run output. Both now fail the node with the cap's reason, through the
//! ordinary failure routing.
//!
//! Each case has a control under a cap large enough for the combination.

use std::sync::Arc;

use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{SystemNodeKind, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher,
    memory::{InMemoryModuleFetcher, InMemoryWorkflowGraphStore},
    minimal_engine,
};
use uuid::Uuid;

/// Each module's output: about 600 bytes serialized.
fn output_of(tag: &str) -> JsonValue {
    json!({ "tag": tag, "body": "x".repeat(580) })
}

/// Under every module's own size, over any two of them combined.
const CAP: usize = 1_000;

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

/// `a → collect ← b`, with `cap` as the per-node limit.
async fn run_collect(cap: usize) -> Result<(), String> {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let graph = WorkflowGraphBuilder::new()
        .add_module("a", a, None)
        .add_module("b", b, None)
        .add_system_node("collect", SystemNodeKind::Collect { label_items: false })
        .edge("a", "collect")
        .edge("b", "collect")
        .build()
        .expect("graph builds");
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_max_node_output_bytes(cap);
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(a, stub_artifact(a))
            .with_module(b, stub_artifact(b)),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    let dispatcher = ScriptedDispatcher::new()
        .with_response(a, output_of("a"))
        .with_response(b, output_of("b"));
    engine
        .run_with_trigger_input_transport(Arc::new(dispatcher), None, json!({}), Uuid::new_v4())
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn a_collect_over_two_outputs_each_under_the_cap_fails_with_the_cap_reason() {
    // Each parent is under the cap on its own (the run reaches the collect).
    assert!(serde_json::to_vec(&output_of("a")).unwrap().len() < CAP);
    let err = run_collect(CAP)
        .await
        .expect_err("an oversized collect must fail");
    assert!(err.contains("Node output too large"), "{err}");
    assert!(err.contains(&format!("{CAP} byte limit")), "{err}");
}

#[tokio::test]
async fn the_same_collect_under_a_cap_that_fits_succeeds() {
    run_collect(10 * CAP)
        .await
        .expect("the control run succeeds");
}

/// A sub-workflow node routes its collapsed child output through
/// `route_system_node_output`; a child with two terminals collapses to a map
/// of both.
async fn run_sub_workflow(cap: usize) -> Result<(), String> {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let child = Uuid::new_v4();
    let child_graph = WorkflowGraphBuilder::new()
        .add_module("a", a, None)
        .add_module("b", b, None)
        .build()
        .expect("child builds");
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "child",
            SystemNodeKind::SubWorkflow {
                workflow_id: child,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent builds");
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_workflow_id(Uuid::new_v4());
    engine.set_max_node_output_bytes(cap);
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(a, stub_artifact(a))
            .with_module(b, stub_artifact(b)),
    ));
    engine.set_graph_store(Arc::new(
        InMemoryWorkflowGraphStore::new().with_graph(child, child_graph),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&parent).unwrap())
        .await
        .expect("load graph");
    let dispatcher = ScriptedDispatcher::new()
        .with_response(a, output_of("a"))
        .with_response(b, output_of("b"));
    engine
        .run_with_trigger_input_transport(Arc::new(dispatcher), None, json!({}), Uuid::new_v4())
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn a_sub_workflow_whose_collapsed_output_is_over_the_cap_fails_with_the_cap_reason() {
    let err = run_sub_workflow(CAP)
        .await
        .expect_err("an oversized sub-workflow output must fail");
    assert!(err.contains("Node output too large"), "{err}");
}

#[tokio::test]
async fn the_same_sub_workflow_under_a_cap_that_fits_succeeds() {
    run_sub_workflow(10 * CAP)
        .await
        .expect("the control run succeeds");
}
