//! `keep_failed_run_outputs`, against a real engine run.
//!
//! The scheduler, the webhook router, crash recovery and the other paths
//! whose failure statement records only the error call this after it, to
//! keep what the nodes that completed had produced. Driven here with the
//! real reactor: what the path's write is handed is what a reader of the
//! failed run will see.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use talos_execution_result_collector::keep_failed_run_outputs;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::WasmModuleArtifact;
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

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

/// `fetch → send`, run once; `send` fails when `fails`.
async fn run(fails: bool) -> ParallelWorkflowEngine {
    let (fetch, send) = (Uuid::new_v4(), Uuid::new_v4());
    let graph = WorkflowGraphBuilder::new()
        .add_module("fetch", fetch, None)
        .add_module("send", send, None)
        .edge("fetch", "send")
        .build()
        .expect("graph builds");
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(fetch, stub_artifact(fetch))
            .with_module(send, stub_artifact(send)),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    let dispatcher = ScriptedDispatcher::new().with_response(fetch, json!({ "items": [1, 2] }));
    let dispatcher = if fails {
        dispatcher.with_error(send, "the send was refused")
    } else {
        dispatcher.with_response(send, json!({ "sent": true }))
    };
    let outcome = engine
        .run_with_trigger_input_transport(Arc::new(dispatcher), None, json!({}), Uuid::new_v4())
        .await;
    assert_eq!(outcome.is_err(), fails);
    engine
}

#[tokio::test]
async fn the_paths_write_is_handed_the_completed_outputs_once() {
    let engine = run(true).await;
    let handed: Arc<Mutex<Vec<Value>>> = Arc::default();
    let attach = |outputs: Value| {
        let handed = handed.clone();
        async move {
            handed.lock().unwrap().push(outputs);
            Ok::<bool, String>(true)
        }
    };

    keep_failed_run_outputs(&engine, Uuid::new_v4(), attach).await;
    assert_eq!(
        *handed.lock().unwrap(),
        vec![json!({ "fetch": { "items": [1, 2] } })],
        "keyed by label, the completed node only, no trigger seed"
    );

    // Taken: a second call has nothing to store and does not call the write.
    keep_failed_run_outputs(&engine, Uuid::new_v4(), attach).await;
    assert_eq!(handed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_run_that_completed_and_a_write_that_fails_are_both_quiet() {
    // Nothing failed: nothing to keep, the write is never called.
    let engine = run(false).await;
    let called = Arc::new(Mutex::new(0u32));
    let count = called.clone();
    keep_failed_run_outputs(&engine, Uuid::new_v4(), |_outputs| async move {
        *count.lock().unwrap() += 1;
        Ok::<bool, String>(true)
    })
    .await;
    assert_eq!(*called.lock().unwrap(), 0);

    // A write that fails, and a row that did not take the outputs, are the
    // caller's to hear about in the log, not to handle: the run's failure is
    // already recorded and this must never turn into a second failure.
    for answer in [Err("the database is away".to_string()), Ok(false)] {
        let engine = run(true).await;
        keep_failed_run_outputs(&engine, Uuid::new_v4(), |_outputs| async move { answer }).await;
    }
}
