//! A run that does not complete still says what its completed nodes produced.
//!
//! Observed (2026-10-13): a run failed at its sixth node, and the outputs of
//! the five that had completed could not be read back by any tool. The
//! reactor keeps node outputs in a map local to the scheduler loop, and an
//! error return dropped the map with the stack frame: the caller got a string.
//! Debugging a failure needs exactly those outputs.
//!
//! The engine now leaves them where the caller can take them, ONCE, scrubbed
//! exactly as a completed run's results are. These drive the real reactor.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, DispatchJob, DispatchResult, ExecutionSanitizer, NodeDispatcher, OutputSanitizer,
    WasmModuleArtifact,
};
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

/// `first → second → third`, loaded into a fresh engine.
async fn chain(ids: [Uuid; 3], timeout: Option<Duration>) -> ParallelWorkflowEngine {
    let mut builder = WorkflowGraphBuilder::new()
        .add_module("first", ids[0], None)
        .add_module("second", ids[1], None)
        .add_module("third", ids[2], None)
        .edge("first", "second")
        .edge("second", "third");
    if let Some(t) = timeout {
        builder = builder.execution_timeout(t);
    }
    let graph = builder.build().expect("graph builds");
    let mut fetcher = InMemoryModuleFetcher::new();
    for id in ids {
        fetcher = fetcher.with_module(id, stub_artifact(id));
    }
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(fetcher));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    engine
}

/// The partial results keyed by node label, without the synthetic trigger.
fn by_label(
    engine: &ParallelWorkflowEngine,
    partial: std::collections::HashMap<Uuid, JsonValue>,
) -> std::collections::BTreeMap<String, JsonValue> {
    partial
        .into_iter()
        .filter_map(|(id, out)| Some((engine.node_labels().get(&id)?.clone(), out)))
        .filter(|(label, _)| label != "__trigger__")
        .collect()
}

#[tokio::test]
async fn a_failed_run_keeps_what_its_completed_nodes_produced_and_gives_it_once() {
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let mut engine = chain(ids, None).await;
    let dispatcher = ScriptedDispatcher::new()
        .with_response(ids[0], json!({ "fetched": 3 }))
        .with_response(ids[1], json!({ "kept": [1, 2] }))
        .with_error(ids[2], "the third step was refused");

    let error = engine
        .run_with_trigger_input_transport(Arc::new(dispatcher), None, json!({}), Uuid::new_v4())
        .await
        .expect_err("the third node fails the run")
        .to_string();
    assert!(error.contains("node 'third' failed"), "{error}");

    let partial = engine
        .take_partial_results()
        .expect("a failed run leaves its completed nodes' outputs");
    let outputs = by_label(&engine, partial);
    assert_eq!(
        outputs.keys().map(String::as_str).collect::<Vec<_>>(),
        ["first", "second"],
        "exactly the nodes that completed, and not the one that failed"
    );
    assert_eq!(outputs["first"]["fetched"], 3);
    assert_eq!(outputs["second"]["kept"], json!([1, 2]));

    // Taken, not kept: the engine does not go on holding a run's outputs.
    assert!(engine.take_partial_results().is_none());
}

#[tokio::test]
async fn a_completed_run_leaves_nothing_behind_and_a_later_run_does_not_see_an_earlier_ones() {
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

    // A run that fails, whose partial results nobody takes…
    let mut engine = chain(ids, None).await;
    let failing = ScriptedDispatcher::new()
        .with_response(ids[0], json!({ "run": "one" }))
        .with_error(ids[1], "stopped")
        .with_response(ids[2], json!({}));
    engine
        .run_with_trigger_input_transport(Arc::new(failing), None, json!({}), Uuid::new_v4())
        .await
        .expect_err("fails");

    // …followed, on the same engine, by a run that completes. Its results
    // are in the returned context; nothing of EITHER run is left to take.
    let healthy = ScriptedDispatcher::new()
        .with_response(ids[0], json!({ "run": "two" }))
        .with_response(ids[1], json!({}))
        .with_response(ids[2], json!({}));
    let ctx = engine
        .run_with_trigger_input_transport(Arc::new(healthy), None, json!({}), Uuid::new_v4())
        .await
        .expect("completes");
    assert_eq!(ctx.results.len(), 4, "three nodes and the trigger seed");
    assert!(
        engine.take_partial_results().is_none(),
        "a completed run left partial results, or an earlier run's survived it"
    );
}

/// Answers the first node at once and never answers the second.
struct StallsAfterFirst {
    first: Uuid,
}

#[async_trait]
impl NodeDispatcher for StallsAfterFirst {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        if job.module_id == self.first {
            return Ok(DispatchResult {
                output: json!({ "fetched": 3 }),
            });
        }
        std::future::pending::<()>().await;
        unreachable!()
    }
}

/// A timeout DROPS the scheduler's future: no line after the loop runs. The
/// outputs are kept all the same, because keeping them is what dropping the
/// map does.
#[tokio::test]
async fn a_run_cut_off_by_its_timeout_keeps_them_too() {
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    // The cap is in whole seconds.
    let mut engine = chain(ids, Some(Duration::from_secs(1))).await;

    let error = engine
        .run_with_trigger_input_transport(
            Arc::new(StallsAfterFirst { first: ids[0] }),
            None,
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .expect_err("the second node never answers")
        .to_string();
    assert!(error.contains("timed out"), "{error}");

    let outputs = by_label(
        &engine,
        engine
            .take_partial_results()
            .expect("kept across a timeout"),
    );
    assert_eq!(
        outputs.keys().map(String::as_str).collect::<Vec<_>>(),
        ["first"]
    );
}

/// Answers the first node at once, never answers the second, and says when
/// the second has been asked: by then the first's output is committed.
struct StallsAfterFirstAndSaysSo {
    first: Uuid,
    second_asked: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl NodeDispatcher for StallsAfterFirstAndSaysSo {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        if job.module_id == self.first {
            return Ok(DispatchResult {
                output: json!({ "fetched": 3 }),
            });
        }
        self.second_asked.notify_one();
        std::future::pending::<()>().await;
        unreachable!()
    }
}

/// A caller that holds the run to a deadline of its OWN (the scheduler does)
/// drops the run from outside: the engine returns nothing, not even an error.
/// The engine is still there, and so are the outputs.
#[tokio::test]
async fn a_run_dropped_by_its_caller_keeps_them_for_the_engine_that_outlives_it() {
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    // No timeout of the engine's own: only the caller stops this run.
    let mut engine = chain(ids, None).await;
    let second_asked = Arc::new(tokio::sync::Notify::new());
    let dispatcher = Arc::new(StallsAfterFirstAndSaysSo {
        first: ids[0],
        second_asked: Arc::clone(&second_asked),
    });

    tokio::select! {
        biased;
        () = second_asked.notified() => {}
        ended = engine.run_with_trigger_input_transport(dispatcher, None, json!({}), Uuid::new_v4()) => {
            panic!("the second node never answers, so the run cannot end: {:?}", ended.map(|_| ()))
        }
    }

    let outputs = by_label(
        &engine,
        engine
            .take_partial_results()
            .expect("kept when the caller drops the run"),
    );
    assert_eq!(
        outputs.keys().map(String::as_str).collect::<Vec<_>>(),
        ["first"]
    );
    assert_eq!(outputs["first"]["fetched"], 3);
}

/// Stands in for the controller's sanitizer: the per-run pass knows one
/// secret VALUE, the stateless pass knows one PATTERN.
struct TwoPassSanitizer;

struct KnowsOneValue;

impl ExecutionSanitizer for KnowsOneValue {
    fn redact_error(&self, s: &str) -> String {
        s.replace("hunter2-value", "[value]")
    }
    fn redact_output(&self, v: &JsonValue) -> JsonValue {
        serde_json::from_str(&v.to_string().replace("hunter2-value", "[value]")).unwrap()
    }
}

impl OutputSanitizer for TwoPassSanitizer {
    fn redact_str(&self, s: &str) -> String {
        s.replace("tok_pattern", "[pattern]")
    }
    fn redact_json(&self, v: &JsonValue) -> JsonValue {
        serde_json::from_str(&v.to_string().replace("tok_pattern", "[pattern]")).unwrap()
    }
    fn new_execution(&self, _node_configs: &[JsonValue]) -> Box<dyn ExecutionSanitizer> {
        Box::new(KnowsOneValue)
    }
}

/// A completed run's results pass two scrubs before they leave the engine. A
/// failed run's must pass the same two: they are about to be stored.
#[tokio::test]
async fn what_a_failed_run_hands_back_is_scrubbed_as_a_completed_runs_results_are() {
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let mut engine = chain(ids, None).await;
    engine.set_output_sanitizer(Arc::new(TwoPassSanitizer));
    let dispatcher = ScriptedDispatcher::new()
        .with_response(
            ids[0],
            json!({ "echoed": "Bearer hunter2-value", "header": "tok_pattern", "kept": "plain" }),
        )
        .with_error(ids[1], "stopped")
        .with_response(ids[2], json!({}));

    engine
        .run_with_trigger_input_transport(Arc::new(dispatcher), None, json!({}), Uuid::new_v4())
        .await
        .expect_err("fails");
    let outputs = by_label(&engine, engine.take_partial_results().expect("kept"));
    let first = &outputs["first"];
    assert_eq!(first["echoed"], "Bearer [value]", "{first}");
    assert_eq!(first["header"], "[pattern]", "{first}");
    assert_eq!(first["kept"], "plain");
}
