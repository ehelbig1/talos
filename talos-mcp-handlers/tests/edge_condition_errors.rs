//! An edge condition that names nothing, from authoring to the test verdict.
//!
//! Observed 2026-10-10: an edge was given the condition `hold.held == true`.
//! An edge condition's scope is the source node's output FIELDS (`held`), so
//! `hold` was unbound, the expression errored, and an edge whose condition
//! errors is not taken. `add_edge` accepted it, `validate_workflow` said
//! nothing, the downstream node never ran, the run was `completed`, and
//! `test_workflow` said `passed: true`.
//!
//! Every step here is production code: the validator's check, the real engine
//! with the production Rhai evaluator, the handler's output projection and the
//! function that decides `passed`. No database.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use talos_engine::expression_evaluator::RhaiEvaluator;
use talos_mcp_handlers::utils::project_engine_results_to_output;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::WasmModuleArtifact;
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use talos_workflow_validation::{
    build_test_assertions, build_test_report, edge_conditions_naming_a_node, TestVerdict,
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

/// hold → apply, the edge carrying `condition`. `hold` returns
/// `{"held": true}`. Returns the graph, the run's output keyed by label, and
/// whether `apply` was dispatched.
async fn run_hold_then_apply(condition: &str) -> (serde_json::Value, serde_json::Value, bool) {
    let (hold, apply) = (Uuid::new_v4(), Uuid::new_v4());
    let graph = WorkflowGraphBuilder::new()
        .add_module("hold", hold, None)
        .add_module("apply", apply, None)
        .edge_condition("hold", "apply", condition)
        .build()
        .expect("graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let fetcher = InMemoryModuleFetcher::new()
        .with_module(hold, stub_artifact(hold))
        .with_module(apply, stub_artifact(apply));
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_expression_evaluator(Arc::new(RhaiEvaluator::new()));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).expect("graph serializes"))
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(hold, json!({"held": true}))
            .with_response(apply, json!({"applied": true})),
    );
    let ctx = engine
        .run_with_trigger_input_transport(dispatcher.clone(), None, json!({}), Uuid::new_v4())
        .await
        .expect("the run completes either way");
    let output = serde_json::Value::Object(project_engine_results_to_output(
        &ctx.results,
        engine.node_labels(),
    ));
    (graph, output, dispatcher.dispatch_count(apply) == 1)
}

#[tokio::test]
async fn a_condition_that_names_its_node_is_warned_about_and_recorded_when_it_runs() {
    let (graph, output, applied) = run_hold_then_apply("hold.held == true").await;

    // Authoring time: the validator (and add_edge, through the same
    // function) names the edge.
    let findings = edge_conditions_naming_a_node(&graph);
    assert_eq!(findings.len(), 1, "{graph}");
    assert_eq!(findings[0].names, ["hold"]);

    // Run time: the rule is unchanged, the edge is not taken.
    assert!(!applied, "an edge whose condition errors is not taken");
    assert!(output.get("apply").is_none(), "apply was skipped: {output}");

    // The defect: the run completed, and the status-only judgement that was
    // the whole of `passed` says true.
    let (_, status_only) = build_test_assertions("completed", "completed", 5, None, &output, None);
    assert!(status_only);

    // Now the run says which edge errored and why, and the test does not pass.
    let report = build_test_report("completed", "completed", 5, None, &output, None, false);
    assert_eq!(report.verdict, TestVerdict::PassedWithFailures);
    assert!(!report.passed);
    assert_eq!(report.edge_condition_errors.len(), 1, "{output}");
    let error = &report.edge_condition_errors[0];
    assert_eq!(error.source, "hold");
    assert_eq!(error.target, "apply");
    assert_eq!(error.condition, "hold.held == true");
    assert!(
        error.error.contains("Variable not found: hold"),
        "{}",
        error.error
    );
}

#[tokio::test]
async fn the_sound_spelling_runs_the_target_and_records_nothing() {
    let (graph, output, applied) = run_hold_then_apply("held == true").await;
    assert!(edge_conditions_naming_a_node(&graph).is_empty());
    assert!(applied);
    assert_eq!(output["hold"], json!({"held": true}), "nothing was added");
    let report = build_test_report("completed", "completed", 5, None, &output, None, false);
    assert_eq!(report.verdict, TestVerdict::Passed);
    assert!(report.passed);
    assert!(report.edge_condition_errors.is_empty());
}

#[tokio::test]
async fn a_condition_that_is_false_is_not_an_error() {
    // `held == false` evaluates, to false: the edge is not taken and nothing
    // is recorded. A branch not taken is an ordinary outcome.
    let (_, output, applied) = run_hold_then_apply("held == false").await;
    assert!(!applied);
    let report = build_test_report("completed", "completed", 5, None, &output, None, false);
    assert_eq!(report.verdict, TestVerdict::Passed);
    assert!(report.edge_condition_errors.is_empty());
}
