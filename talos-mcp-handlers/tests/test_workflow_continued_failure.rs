//! `test_workflow` over a run that completed past a node that failed.
//!
//! Observed 2026-10-11: a phone-notification node ran out of fuel under
//! `continue_on_error`, the run reached `completed`, and `test_workflow`
//! answered `passed: true`. In production that is a notification that never
//! arrives.
//!
//! This drives the real engine (a composer, a notifier that fails and is
//! continued past, a sender after it), projects the results the way the
//! handler does (`project_engine_results_to_output`), and judges them with
//! the function the handler calls (`build_test_report`). No database.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use talos_mcp_handlers::utils::project_engine_results_to_output;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::WasmModuleArtifact;
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use talos_workflow_validation::{
    build_test_assertions, build_test_report, FailureHandling, TestVerdict,
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

/// compose → notify → send, where `notify` fails. Returns the run's output
/// keyed by node label, as `test_workflow` builds it.
async fn run_past_a_failed_notifier(continue_on_error: bool) -> Result<serde_json::Value, String> {
    let (compose, notify, send) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mut builder = WorkflowGraphBuilder::new()
        .add_module("compose", compose, None)
        .add_module("notify", notify, None)
        .add_module("send", send, None)
        .edge("compose", "notify")
        .edge("notify", "send");
    if continue_on_error {
        builder = builder.with_continue_on_error("notify");
    }
    let graph = builder.build().expect("graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    for module in [compose, notify, send] {
        fetcher = fetcher.with_module(module, stub_artifact(module));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).expect("graph serializes"))
        .await
        .expect("graph loads");

    let dispatcher = ScriptedDispatcher::new()
        .with_response(compose, json!({"notification": {"title": "Your morning"}}))
        .with_error(notify, "Component returned error: fuel exhausted")
        .with_response(send, json!({"sent": true}));
    let ctx = engine
        .run_with_trigger_input_transport(Arc::new(dispatcher), None, json!({}), Uuid::new_v4())
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::Value::Object(project_engine_results_to_output(
        &ctx.results,
        engine.node_labels(),
    )))
}

#[tokio::test]
async fn a_run_that_completed_past_a_failed_node_does_not_pass_and_names_the_node() {
    let output = run_past_a_failed_notifier(true)
        .await
        .expect("continue_on_error keeps the run alive");
    // The run really did go on: the node after the failure ran.
    assert_eq!(output["send"]["sent"], true, "{output}");

    // The defect: until 2026-10-12 this was the whole of `passed`, and over
    // this run it is true.
    let (_, status_only) = build_test_assertions("completed", "completed", 5, None, &output, None);
    assert!(
        status_only,
        "the assertions alone cannot see the failed node"
    );

    let report = build_test_report("completed", "completed", 5, None, &output, None, false);
    assert_eq!(report.verdict, TestVerdict::PassedWithFailures);
    assert!(
        !report.passed,
        "a completed run past a failed node read as passed"
    );
    assert_eq!(report.continued_failures.len(), 1, "{output}");
    let failure = &report.continued_failures[0];
    assert_eq!(failure.node, "notify");
    assert_eq!(failure.handling, FailureHandling::ContinueOnError);
    assert_eq!(failure.error_class, "fuel_exhaustion");
    assert!(failure.message.contains("fuel exhausted"), "{failure:?}");

    // Allowed by the caller: still listed, still not a plain pass.
    let allowed = build_test_report("completed", "completed", 5, None, &output, None, true);
    assert!(allowed.passed);
    assert_eq!(allowed.verdict, TestVerdict::PassedWithFailures);
    assert_eq!(allowed.continued_failures.len(), 1);
}

#[tokio::test]
async fn the_same_run_without_continue_on_error_fails_outright() {
    // The control: without the opt-in the engine fails the run, and the
    // handler judges status `failed` against the default `completed`.
    let err = run_past_a_failed_notifier(false)
        .await
        .expect_err("a failed node with no opt-in fails the run");
    assert!(err.contains("notify"), "{err}");
    let report = build_test_report(
        "failed",
        "completed",
        5,
        None,
        &json!({"error": err}),
        None,
        false,
    );
    assert_eq!(report.verdict, TestVerdict::Failed);
    assert!(!report.passed);
    assert!(report.continued_failures.is_empty());
}
