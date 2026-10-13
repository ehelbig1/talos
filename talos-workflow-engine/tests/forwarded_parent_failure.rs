//! A node that forwards its parent's output is not failed by what it
//! forwards.
//!
//! Observed on a live graph (2026-10-13):
//!
//! ```text
//! a ─┬─► optional (module, continue_on_error) ─► links (action_links) ─► send_links
//!    └─► compose ─► send_main
//! ```
//!
//! `optional` failed, as its author allowed. Its committed output is the
//! `__error` envelope `continue_on_error` writes. `links` passes its parent's
//! output on, so ITS output was that same envelope, and the system-node
//! router read the envelope as `links` reporting a failure. `links` has no
//! `continue_on_error` of its own, so the run failed with "node 'links'
//! failed: <optional's error>", the main branch was cut off, and the timeline
//! showed `links` both failed and completed.
//!
//! The author said the optional branch may fail. A node that only transforms
//! and forwards did not fail; what it forwards already says so, and
//! `__degraded_inputs__` names the node that did.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    action_links::ACTION_LINKS_REPORT, reserved_keys::output_reports_error, BoxError,
    ExpressionEvaluator, SystemNodeKind, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{
    capture::CaptureEventSink, dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher,
    minimal_engine,
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

/// The condition the author wrote on `links → send_links`.
const NOT_AN_ERROR: &str = "is_error == false";

/// Stands in for the controller's Rhai evaluator on the ONE condition this
/// graph has. `minimal_engine` wires an evaluator that answers `true` without
/// reading anything, which would take the edge whatever the engine handed it.
/// The real evaluator binds `is_error` from the context with the classifier
/// used here (`talos-engine`'s `rhai_helpers`, tested there; this crate
/// cannot depend on it). What this proves is the engine's half: the condition
/// IS evaluated, against the forwarded envelope.
struct IsErrorEvaluator;

impl ExpressionEvaluator for IsErrorEvaluator {
    fn eval_bool(&self, expression: &str, context: &JsonValue) -> bool {
        self.try_eval_bool(expression, context).unwrap_or(false)
    }
    fn try_eval_bool(&self, expression: &str, context: &JsonValue) -> Result<bool, BoxError> {
        if expression == NOT_AN_ERROR {
            Ok(!output_reports_error(context))
        } else {
            Err(format!("unexpected expression: {expression}").into())
        }
    }
    fn eval_i64(&self, _e: &str, _c: &JsonValue) -> Option<i64> {
        None
    }
    fn eval_json(&self, expression: &str, _c: &JsonValue) -> Result<JsonValue, BoxError> {
        Err(format!("unexpected expression: {expression}").into())
    }
}

struct Modules {
    a: Uuid,
    optional: Uuid,
    compose: Uuid,
    send_main: Uuid,
    send_links: Uuid,
}

struct Outcome {
    run: Result<HashMap<String, JsonValue>, String>,
    dispatcher: ScriptedDispatcher,
    modules: Modules,
    /// Per node label, the statuses of its terminal events in order.
    terminal: BTreeMap<String, Vec<String>>,
}

/// Run the observed graph. `optional_fails` is the only thing that varies.
async fn run_graph(optional_fails: bool) -> Outcome {
    let modules = Modules {
        a: Uuid::new_v4(),
        optional: Uuid::new_v4(),
        compose: Uuid::new_v4(),
        send_main: Uuid::new_v4(),
        send_links: Uuid::new_v4(),
    };
    let graph = WorkflowGraphBuilder::new()
        .add_module("a", modules.a, None)
        .add_module("optional", modules.optional, None)
        .with_continue_on_error("optional")
        .add_system_node(
            "links",
            SystemNodeKind::ActionLinks {
                targets: BTreeMap::new(),
                ttl_hours: None,
            },
        )
        .add_module("send_links", modules.send_links, None)
        .add_module("compose", modules.compose, None)
        .add_module("send_main", modules.send_main, None)
        .edge("a", "optional")
        .edge("optional", "links")
        // The author's own guard: send the links only when there is
        // something to send.
        .edge_condition("links", "send_links", NOT_AN_ERROR)
        .edge("a", "compose")
        .edge("compose", "send_main")
        .build()
        .expect("graph builds");

    let mut dispatcher = ScriptedDispatcher::new()
        .with_response(modules.a, json!({ "ok": true }))
        .with_response(modules.compose, json!({ "subject": "main" }))
        .with_response(modules.send_main, json!({ "sent": true }))
        .with_response(modules.send_links, json!({ "sent": true }));
    dispatcher = if optional_fails {
        dispatcher.with_error(modules.optional, "the optional lookup was refused")
    } else {
        dispatcher.with_response(modules.optional, json!({ "html": "nothing to link" }))
    };

    let sink = CaptureEventSink::new();
    let mut fetcher = InMemoryModuleFetcher::new();
    for id in [
        modules.a,
        modules.optional,
        modules.compose,
        modules.send_main,
        modules.send_links,
    ] {
        fetcher = fetcher.with_module(id, stub_artifact(id));
    }
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_event_sink(Arc::new(sink.clone()));
    engine.set_expression_evaluator(Arc::new(IsErrorEvaluator));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    let labels = engine.node_labels().clone();

    let run = engine
        .run_with_trigger_input_transport(
            Arc::new(dispatcher.clone()),
            None,
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .map(|ctx| {
            ctx.results
                .iter()
                .filter_map(|(id, out)| Some((labels.get(id)?.clone(), out.clone())))
                .collect()
        })
        .map_err(|e| e.to_string());

    // A system node's lifecycle events are written by a spawned task.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut terminal: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for event in sink.events() {
        if !matches!(event.event_type.as_str(), "node_completed" | "node_failed") {
            continue;
        }
        let Some(label) = event.node_id.and_then(|id| labels.get(&id)) else {
            continue;
        };
        terminal
            .entry(label.clone())
            .or_default()
            .push(event.status);
    }

    Outcome {
        run,
        dispatcher,
        modules,
        terminal,
    }
}

#[tokio::test]
async fn an_optional_branch_that_fails_does_not_fail_the_run_through_the_node_that_forwards_it() {
    let outcome = run_graph(true).await;

    let results = outcome
        .run
        .as_ref()
        .unwrap_or_else(|e| panic!("the run failed on a branch its author made optional: {e}"));

    // The main branch ran to its end.
    assert_eq!(
        outcome.dispatcher.dispatch_count(outcome.modules.send_main),
        1,
        "the main notification was not sent"
    );
    // The links branch stopped at the author's condition.
    assert_eq!(
        outcome
            .dispatcher
            .dispatch_count(outcome.modules.send_links),
        0,
        "send_links ran on a failed branch"
    );

    // `links` forwarded what it was given, and said it minted nothing.
    let links = &results["links"];
    assert_eq!(links["__error"], true, "{links}");
    assert_eq!(links["__continued"], true, "{links}");
    assert!(
        links["error_message"]
            .as_str()
            .is_some_and(|m| m.contains("the optional lookup was refused")),
        "{links}"
    );
    assert_eq!(links[ACTION_LINKS_REPORT]["minted"], 0, "{links}");

    // One fate per node: `optional` failed; `links` completed and did not
    // also fail.
    assert_eq!(
        outcome.terminal.get("optional").map(Vec::as_slice),
        Some(&["Failed".to_string()][..]),
        "{:?}",
        outcome.terminal
    );
    assert_eq!(
        outcome.terminal.get("links").map(Vec::as_slice),
        Some(&["Completed".to_string()][..]),
        "{:?}",
        outcome.terminal
    );
    for (label, statuses) in &outcome.terminal {
        let failed = statuses.iter().any(|s| s == "Failed");
        let completed = statuses.iter().any(|s| s == "Completed");
        assert!(
            !(failed && completed),
            "{label} is recorded both failed and completed: {statuses:?}"
        );
    }
}

/// The control: nothing fails, and both sends go out.
#[tokio::test]
async fn the_same_graph_with_a_healthy_optional_branch_sends_both() {
    let outcome = run_graph(false).await;
    let results = outcome.run.as_ref().expect("a healthy run completes");

    assert_eq!(
        outcome.dispatcher.dispatch_count(outcome.modules.send_main),
        1
    );
    assert_eq!(
        outcome
            .dispatcher
            .dispatch_count(outcome.modules.send_links),
        1
    );
    assert_eq!(
        results["links"],
        json!({
            "html": "nothing to link",
            ACTION_LINKS_REPORT: {
                "available": true, "requested": 0, "minted": 0, "not_minted": [],
            },
        })
    );
}

/// A gate is not a forwarder: it judges what it is given, and one that passes
/// a failed parent's envelope on still fails, as it did before. What changed
/// is the message. It used to read "node 'gate' failed: <the parent's error
/// text>", which sends a reader to the gate. It now also names the node that
/// had already failed.
#[tokio::test]
async fn a_run_that_fails_downstream_of_a_continued_failure_names_the_node_that_failed_first() {
    let fetch = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("fetch", fetch, None)
        .with_continue_on_error("fetch")
        .add_system_node(
            "gate",
            SystemNodeKind::ConfidenceGate {
                threshold: 0.0,
                confidence_path: "confidence".into(),
                on_low_confidence: "passthrough".into(),
            },
        )
        .edge("fetch", "gate")
        .build()
        .expect("graph builds");

    let run = |fails: bool| {
        let graph = graph.clone();
        async move {
            let mut engine = minimal_engine();
            engine.set_user_id(Uuid::new_v4());
            engine.set_module_fetcher(Arc::new(
                InMemoryModuleFetcher::new().with_module(fetch, stub_artifact(fetch)),
            ));
            engine
                .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
                .await
                .expect("load graph");
            let dispatcher = if fails {
                ScriptedDispatcher::new().with_error(fetch, "the upstream API was down")
            } else {
                ScriptedDispatcher::new().with_response(fetch, json!({ "confidence": 0.9 }))
            };
            engine
                .run_with_trigger_input_transport(
                    Arc::new(dispatcher),
                    None,
                    json!({}),
                    Uuid::new_v4(),
                )
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    };

    let error = run(true).await.expect_err("the gate still fails the run");
    assert!(
        error.contains("node 'gate' failed: the upstream API was down"),
        "{error}"
    );
    assert!(
        error.contains("(already failed upstream: fetch)"),
        "the message does not name the node that failed first: {error}"
    );

    // The control: nothing upstream failed, and nothing is appended anywhere.
    run(false).await.expect("a healthy run completes");
}
