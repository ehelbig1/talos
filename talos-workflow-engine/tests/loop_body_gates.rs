//! A `loop` node's BODY dispatch passes the same pre-dispatch gates as a
//! single-node dispatch: capability-world ceiling, approval, per-module rate
//! limit, and the method-aware retry budget.
//!
//! Until 2026-09-25 `run_loop_iterations` hand-built its `DispatchJob` and
//! applied none of them. The ceiling was checked only at
//! `engine_dispatch_single.rs` and `engine_dispatch_pipeline.rs`, the approval
//! gate likewise, `check_rate_limit` only in the reactor's single-node branch,
//! and the body carried a literal `max_retries: 2` whatever its methods or
//! world. So wrapping a module in a loop was a way around every one of them.
//!
//! These drive the real reactor through `run_with_trigger_input_transport` (the
//! production entry, chain batching off) with a scripted dispatcher. Each gate
//! test has its CONTROL: the same graph with the gate satisfied must dispatch
//! the body, so "zero dispatches" cannot pass by the loop failing for some
//! other reason.
//!
//! The graph is `loop -> body`: the body is ALSO a node in its own right, so
//! after a loop that finishes it runs once more through the single-node path.
//! A loop-body job is told apart by `emit_retry_events == false` (the loop
//! path's documented setting; the single-node path sets `true`).

use std::sync::Arc;

use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    default_max_retries_for_module, DispatchJob, SystemNodeKind, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{
    approval::AlwaysPendingGate, dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher,
    minimal_engine,
};
use uuid::Uuid;

const ITERATIONS: u64 = 3;

fn artifact(id: Uuid, world: &str, methods: &[&str]) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: world.into(),
        allowed_hosts: vec![],
        allowed_methods: methods.iter().map(|m| (*m).to_string()).collect(),
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

/// `loop -> body`, the loop pointing at `body` and running `ITERATIONS` times
/// (the harness's expression evaluator answers every condition `true`).
/// `retry` optionally declares an explicit `retry_count` on the body node.
fn loop_graph(body_module: Uuid, retry: Option<(u32, u64)>) -> String {
    let mut b = WorkflowGraphBuilder::new()
        .add_system_node(
            "loop",
            SystemNodeKind::Loop {
                max_iterations: ITERATIONS as u32,
                condition: "true".into(),
            },
        )
        .add_module("body", body_module, None)
        .edge("loop", "body");
    if let Some((count, backoff)) = retry {
        b = b.with_retry("body", count, backoff, None, None);
    }
    let mut g = b.build().expect("graph builds");
    let loop_node = g["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|n| n["id"] == "loop")
        .unwrap();
    loop_node["data"]["body_node_id"] = json!("body");
    serde_json::to_string(&g).unwrap()
}

async fn engine_with(fetcher: InMemoryModuleFetcher, graph: &str) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.load_graph_from_json(graph).await.expect("load");
    engine
}

/// The jobs the LOOP dispatched for the body (not the body's own later run).
fn loop_jobs(d: &ScriptedDispatcher, body: Uuid) -> Vec<DispatchJob> {
    d.jobs()
        .into_iter()
        .filter(|j| j.module_id == body && !j.emit_retry_events)
        .collect()
}

async fn run(
    engine: &mut ParallelWorkflowEngine,
    d: &Arc<ScriptedDispatcher>,
) -> Result<talos_workflow_engine_core::WorkflowContext, String> {
    engine
        .run_with_trigger_input_transport(d.clone(), None, json!({}), Uuid::new_v4())
        .await
        .map_err(|e| e.to_string())
}

// ── Capability-world ceiling ────────────────────────────────────────

#[tokio::test]
async fn a_loop_body_above_the_actors_capability_ceiling_is_never_dispatched() {
    let body = Uuid::new_v4();
    let fetcher =
        InMemoryModuleFetcher::new().with_module(body, artifact(body, "automation-node", &["GET"]));
    let mut engine = engine_with(fetcher, &loop_graph(body, None)).await;
    engine.set_max_capability_world(Some("minimal-node".to_string()));
    let d = Arc::new(ScriptedDispatcher::new().with_response(body, json!({"ok": true})));

    let err = run(&mut engine, &d)
        .await
        .expect_err("the loop body exceeds the ceiling");

    assert_eq!(
        loop_jobs(&d, body).len(),
        0,
        "the loop dispatched a body the actor's ceiling refuses"
    );
    assert_eq!(d.total_dispatches(), 0, "nothing reached a worker");
    assert!(
        err.contains("Loop node") && err.contains("capability ceiling violation"),
        "the LOOP fails, naming the ceiling: {err}"
    );
}

#[tokio::test]
async fn control_a_loop_body_within_the_ceiling_runs_every_iteration() {
    let body = Uuid::new_v4();
    let fetcher =
        InMemoryModuleFetcher::new().with_module(body, artifact(body, "minimal-node", &[]));
    let mut engine = engine_with(fetcher, &loop_graph(body, None)).await;
    engine.set_max_capability_world(Some("automation-node".to_string()));
    let d = Arc::new(ScriptedDispatcher::new().with_response(body, json!({"ok": true})));

    run(&mut engine, &d).await.expect("within the ceiling");
    assert_eq!(loop_jobs(&d, body).len(), ITERATIONS as usize);
}

// ── Approval gate ───────────────────────────────────────────────────

#[tokio::test]
async fn an_approval_gated_loop_body_waits_for_approval() {
    let body = Uuid::new_v4();
    let mut gated = artifact(body, "http-node", &["POST"]);
    gated.requires_approval_for = vec!["send".into()];
    let fetcher = InMemoryModuleFetcher::new().with_module(body, gated);
    let mut engine = engine_with(fetcher, &loop_graph(body, None)).await;
    engine.set_approval_gate(Arc::new(AlwaysPendingGate::new()));
    let d = Arc::new(ScriptedDispatcher::new().with_response(body, json!({"ok": true})));

    let err = run(&mut engine, &d).await.expect_err("approval is pending");

    assert_eq!(
        loop_jobs(&d, body).len(),
        0,
        "the loop sent an approval-gated body before it was approved"
    );
    assert!(
        err.contains("Loop node") && err.contains("[APPROVAL_PENDING]"),
        "the LOOP pauses with the single-node path's own marker: {err}"
    );
}

#[tokio::test]
async fn control_an_approved_loop_body_runs() {
    let body = Uuid::new_v4();
    let mut gated = artifact(body, "http-node", &["POST"]);
    gated.requires_approval_for = vec!["send".into()];
    // `minimal_engine` wires `AlwaysApproveGate`.
    let fetcher = InMemoryModuleFetcher::new().with_module(body, gated);
    let mut engine = engine_with(fetcher, &loop_graph(body, None)).await;
    let d = Arc::new(ScriptedDispatcher::new().with_response(body, json!({"ok": true})));

    run(&mut engine, &d).await.expect("approved");
    assert_eq!(loop_jobs(&d, body).len(), ITERATIONS as usize);
}

// ── Per-module rate limit ───────────────────────────────────────────

#[tokio::test]
async fn a_rate_limited_loop_body_stops_at_its_limit() {
    let body = Uuid::new_v4();
    // One dispatch a minute. A fresh module id, so the process-global
    // in-memory counter holds nothing for it from another test.
    let fetcher = InMemoryModuleFetcher::new()
        .with_module(body, artifact(body, "minimal-node", &[]))
        .with_rate_limit(body, 1);
    let mut engine = engine_with(fetcher, &loop_graph(body, None)).await;
    let d = Arc::new(ScriptedDispatcher::new().with_response(body, json!({"ok": true})));

    let err = run(&mut engine, &d)
        .await
        .expect_err("the second iteration exceeds 1/min");

    assert_eq!(
        loop_jobs(&d, body).len(),
        1,
        "a body limited to 1/min must dispatch once, not once per iteration"
    );
    assert!(
        err.contains("Loop node") && err.contains("rate limit"),
        "the LOOP stops on the rate limit: {err}"
    );
}

// ── Method-aware retry budget ───────────────────────────────────────

#[tokio::test]
async fn a_state_changing_loop_body_gets_no_blind_retries() {
    let body = Uuid::new_v4();
    let fetcher =
        InMemoryModuleFetcher::new().with_module(body, artifact(body, "http-node", &["POST"]));
    let mut engine = engine_with(fetcher, &loop_graph(body, None)).await;
    let d = Arc::new(ScriptedDispatcher::new().with_response(body, json!({"ok": true})));

    run(&mut engine, &d).await.expect("runs");
    let jobs = loop_jobs(&d, body);
    assert_eq!(jobs.len(), ITERATIONS as usize);
    for j in &jobs {
        assert_eq!(
            j.max_retries, 0,
            "a POST body that declared no retry_count must not be re-sent on a transport \
             failure (was a hardcoded 2)"
        );
    }
}

#[tokio::test]
async fn control_a_read_only_loop_body_keeps_the_method_aware_default() {
    let body = Uuid::new_v4();
    let fetcher =
        InMemoryModuleFetcher::new().with_module(body, artifact(body, "http-node", &["GET"]));
    let mut engine = engine_with(fetcher, &loop_graph(body, None)).await;
    let d = Arc::new(ScriptedDispatcher::new().with_response(body, json!({"ok": true})));

    run(&mut engine, &d).await.expect("runs");
    let expected = default_max_retries_for_module(&["GET".to_string()], Some("http-node"));
    assert!(expected > 0, "a GET-only http-node earns transient retries");
    for j in loop_jobs(&d, body) {
        assert_eq!(j.max_retries, expected);
    }
}

#[tokio::test]
async fn a_loop_bodys_explicit_retry_policy_is_honoured() {
    let body = Uuid::new_v4();
    let fetcher =
        InMemoryModuleFetcher::new().with_module(body, artifact(body, "http-node", &["POST"]));
    // 1, not something larger: an actor-less engine clamps a declared count
    // to `MAX_RETRIES_UNBUDGETED` (3) at graph load, and 1 is also not the old
    // literal 2, so the assertion can only pass by reading the node's policy.
    let mut engine = engine_with(fetcher, &loop_graph(body, Some((1, 1234)))).await;
    let d = Arc::new(ScriptedDispatcher::new().with_response(body, json!({"ok": true})));

    run(&mut engine, &d).await.expect("runs");
    let jobs = loop_jobs(&d, body);
    assert_eq!(jobs.len(), ITERATIONS as usize);
    for j in jobs {
        assert_eq!(j.max_retries, 1, "the author's retry_count wins");
        assert_eq!(j.backoff_ms, 1234, "and so does their backoff");
    }
}
