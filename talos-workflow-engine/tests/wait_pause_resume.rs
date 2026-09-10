//! End-to-end pause-and-resume on `SystemNodeKind::Wait`.
//!
//! Locks in the contract documented on [`SystemNodeKind::Wait`]:
//!
//! 1. A fresh run that reaches a `Wait` node returns a
//!    [`WorkflowContext`] with `waiting: true` and the Wait node's
//!    `__waiting__` envelope in `results`. The reactor stops short
//!    of dispatching anything past the Wait.
//! 2. A resume via [`run_with_seed_with_transport`] with `seed[wait_id]`
//!    set to the external resume value treats the Wait node as
//!    completed. Successors run with the seeded value visible via
//!    their gathered inputs.
//! 3. Multiple Wait nodes in series are supported — each pause needs
//!    its own resume call. Round-tripping the full snapshot back into
//!    the next seed is the expected pattern.
//!
//! These tests use a fan-out / fan-in graph (no linear chains) so the
//! engine's pipeline-chain optimisation doesn't interfere with the
//! per-node `module_id`-keyed `ScriptedDispatcher`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{SystemNodeKind, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

fn stub_artifact(module_id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id,
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

/// A graph with shape:
///
/// ```text
///   start ─→ wait ─→ after
///         ─→ sibling
/// ```
///
/// `start` fan-outs to `wait` and `sibling` so the chain detector
/// doesn't batch start+wait into a pipeline (which would break the
/// per-node dispatch path the test relies on). `wait` is the pause
/// point; `after` runs after the resume.
fn build_pause_graph() -> (
    serde_json::Value,
    Uuid, /* start_module */
    Uuid, /* sibling_module */
    Uuid, /* after_module */
) {
    let start_mod = Uuid::new_v4();
    let sibling_mod = Uuid::new_v4();
    let after_mod = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("start", start_mod, None)
        .add_module("sibling", sibling_mod, None)
        .add_system_node(
            "wait",
            SystemNodeKind::Wait {
                message: Some("awaiting approval".into()),
            },
        )
        .add_module("after", after_mod, None)
        .edge("start", "wait")
        .edge("start", "sibling")
        .edge("wait", "after")
        .build()
        .expect("graph builds");
    (graph, start_mod, sibling_mod, after_mod)
}

fn engine_with(start_mod: Uuid, sibling_mod: Uuid, after_mod: Uuid) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(start_mod, stub_artifact(start_mod))
            .with_module(sibling_mod, stub_artifact(sibling_mod))
            .with_module(after_mod, stub_artifact(after_mod)),
    ));
    engine
}

#[tokio::test]
async fn wait_node_pauses_fresh_run_and_emits_envelope() {
    let (graph_json, start_mod, sibling_mod, after_mod) = build_pause_graph();
    let mut engine = engine_with(start_mod, sibling_mod, after_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(start_mod, json!({"output": "start ran"}))
            .with_response(sibling_mod, json!({"output": "sibling ran"}))
            // Scripted on purpose — proves it never gets called pre-resume.
            .with_response(after_mod, json!({"output": "after ran"})),
    );

    let ctx = engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect("first run returns Ok with waiting flag, not Err");

    assert!(ctx.waiting, "WorkflowContext.waiting must be true on pause");
    // Find the Wait node's id by label so we can assert on its envelope.
    let wait_id = engine
        .node_labels()
        .iter()
        .find_map(|(id, label)| (label == "wait").then_some(*id))
        .expect("wait node was added");
    let envelope = ctx.results.get(&wait_id).expect("wait output is recorded");
    assert_eq!(envelope["__waiting__"].as_bool(), Some(true));
    assert_eq!(envelope["message"].as_str(), Some("awaiting approval"));

    // The successor must NOT have run pre-resume.
    let after_id = engine
        .node_labels()
        .iter()
        .find_map(|(id, label)| (label == "after").then_some(*id))
        .expect("after node was added");
    assert!(
        !ctx.results.contains_key(&after_id),
        "after-Wait successor must not run before resume; got results: {:?}",
        ctx.results
    );
    assert_eq!(
        dispatcher.dispatch_count(after_mod),
        0,
        "after's module must not have been dispatched"
    );
}

#[tokio::test]
async fn resume_with_seeded_wait_value_runs_only_remaining_nodes() {
    let (graph_json, start_mod, sibling_mod, after_mod) = build_pause_graph();
    let mut engine = engine_with(start_mod, sibling_mod, after_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(start_mod, json!({"output": "start ran"}))
            .with_response(sibling_mod, json!({"output": "sibling ran"}))
            .with_response(after_mod, json!({"output": "after ran"})),
    );

    let exec_id = Uuid::new_v4();
    let pause_ctx = engine
        .run_with_transport(dispatcher.clone(), None, exec_id)
        .await
        .expect("first run pauses");
    assert!(pause_ctx.waiting);

    // Build the resume seed: every node currently in results, with the
    // Wait node's envelope replaced by the external resume value.
    let wait_id = engine
        .node_labels()
        .iter()
        .find_map(|(id, label)| (label == "wait").then_some(*id))
        .expect("wait id");
    let mut seed: HashMap<Uuid, serde_json::Value> = pause_ctx.results.clone();
    seed.insert(wait_id, json!({"approved_by": "alice"}));

    // Same execution_id so observability + audit rows correlate.
    let resume_ctx = engine
        .run_with_seed_with_transport(dispatcher.clone(), None, seed, exec_id)
        .await
        .expect("resume completes");
    assert!(
        !resume_ctx.waiting,
        "resume must complete cleanly, not re-pause"
    );

    // `after` must have run on resume.
    let after_id = engine
        .node_labels()
        .iter()
        .find_map(|(id, label)| (label == "after").then_some(*id))
        .expect("after id");
    assert!(resume_ctx.results.contains_key(&after_id));
    assert_eq!(
        dispatcher.dispatch_count(after_mod),
        1,
        "after must have been dispatched exactly once on resume"
    );

    // `start` and `sibling` were seeded — their dispatchers must not
    // have re-run.
    assert_eq!(dispatcher.dispatch_count(start_mod), 1);
    assert_eq!(dispatcher.dispatch_count(sibling_mod), 1);
}

#[tokio::test]
async fn two_wait_nodes_in_series_pause_resume_pause_resume() {
    // Multi-stage approval pattern: a workflow gates on two distinct
    // human inputs (e.g. legal sign-off → exec sign-off), each modeled
    // as its own Wait node. This test covers the full cycle:
    //
    //   start ─→ wait_a ─→ middle ─→ wait_b ─→ finalize
    //         ─→ sibling
    //
    // Run 1: pauses at wait_a. Snapshot the partial results.
    // Run 2: resume seeded with wait_a's external value. The reactor
    //        runs `middle`, then pauses at wait_b. Snapshot again.
    // Run 3: resume seeded with both wait values. `finalize` runs and
    //        the workflow completes.
    //
    // The big invariant: the seed map carried into Run 3 must contain
    // BOTH wait nodes' values. Otherwise the engine would treat
    // wait_a as un-completed and re-pause at it instead of advancing
    // past wait_b. Locks in the "round-trip the snapshot" pattern
    // documented in docs/checkpoint-lifecycle.md.
    let start_mod = Uuid::new_v4();
    let sibling_mod = Uuid::new_v4();
    let middle_mod = Uuid::new_v4();
    let finalize_mod = Uuid::new_v4();

    let graph = WorkflowGraphBuilder::new()
        .add_module("start", start_mod, None)
        .add_module("sibling", sibling_mod, None)
        .add_system_node(
            "wait_a",
            SystemNodeKind::Wait {
                message: Some("legal review".into()),
            },
        )
        .add_module("middle", middle_mod, None)
        .add_system_node(
            "wait_b",
            SystemNodeKind::Wait {
                message: Some("exec sign-off".into()),
            },
        )
        .add_module("finalize", finalize_mod, None)
        .edge("start", "wait_a")
        .edge("start", "sibling")
        .edge("wait_a", "middle")
        .edge("middle", "wait_b")
        .edge("wait_b", "finalize")
        .build()
        .expect("graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(start_mod, stub_artifact(start_mod))
            .with_module(sibling_mod, stub_artifact(sibling_mod))
            .with_module(middle_mod, stub_artifact(middle_mod))
            .with_module(finalize_mod, stub_artifact(finalize_mod)),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(start_mod, json!({"output": "start"}))
            .with_response(sibling_mod, json!({"output": "sibling"}))
            .with_response(middle_mod, json!({"output": "middle"}))
            .with_response(finalize_mod, json!({"output": "finalize"})),
    );

    let exec_id = Uuid::new_v4();
    let label_id = |name: &str| -> Uuid {
        engine
            .node_labels()
            .iter()
            .find_map(|(id, label)| (label == name).then_some(*id))
            .unwrap_or_else(|| panic!("missing label {name}"))
    };

    // ── Run 1: fresh start → pauses at wait_a ───────────────────────
    let pause1 = engine
        .run_with_transport(dispatcher.clone(), None, exec_id)
        .await
        .expect("run 1 returns Ok with waiting flag");
    assert!(pause1.waiting, "first run should pause");
    let wait_a = label_id("wait_a");
    let wait_b = label_id("wait_b");
    let middle = label_id("middle");
    let finalize = label_id("finalize");
    assert!(pause1.results.contains_key(&wait_a));
    assert!(
        !pause1.results.contains_key(&middle),
        "middle should not have run pre-resume"
    );
    assert_eq!(dispatcher.dispatch_count(middle_mod), 0);
    assert_eq!(dispatcher.dispatch_count(finalize_mod), 0);

    // ── Run 2: resume with wait_a seeded → pauses at wait_b ─────────
    let mut seed_2 = pause1.results.clone();
    seed_2.insert(wait_a, json!({"approved_by": "legal"}));
    let pause2 = engine
        .run_with_seed_with_transport(dispatcher.clone(), None, seed_2, exec_id)
        .await
        .expect("run 2 returns Ok with waiting flag");
    assert!(pause2.waiting, "second run should pause at wait_b");
    assert!(pause2.results.contains_key(&middle), "middle ran on resume");
    assert!(pause2.results.contains_key(&wait_b), "wait_b paused");
    assert!(
        !pause2.results.contains_key(&finalize),
        "finalize must not run before wait_b's resume"
    );
    assert_eq!(dispatcher.dispatch_count(middle_mod), 1);
    assert_eq!(dispatcher.dispatch_count(finalize_mod), 0);

    // ── Run 3: resume with BOTH wait values seeded → completes ──────
    // Crucial detail: the seed must carry wait_a's value too. Drop it
    // and the engine re-pauses at wait_a instead of advancing past
    // wait_b — that's the documented "round-trip the snapshot"
    // pattern. We exercise it explicitly.
    let mut seed_3 = pause2.results.clone();
    seed_3.insert(wait_a, json!({"approved_by": "legal"}));
    seed_3.insert(wait_b, json!({"approved_by": "ceo"}));
    let done = engine
        .run_with_seed_with_transport(dispatcher.clone(), None, seed_3, exec_id)
        .await
        .expect("run 3 completes cleanly");
    assert!(!done.waiting, "third run should not pause");
    assert!(
        done.results.contains_key(&finalize),
        "finalize must run on the second resume"
    );
    assert_eq!(dispatcher.dispatch_count(finalize_mod), 1);
}

#[tokio::test]
async fn wait_without_message_omits_message_key() {
    // Sanity: Wait { message: None } produces a minimal envelope.
    // Locks in the documented "no `message` key when absent" shape so
    // resume orchestration can't accidentally start expecting it.
    let start_mod = Uuid::new_v4();
    let sibling_mod = Uuid::new_v4();
    let after_mod = Uuid::new_v4();
    // `sibling` used to be neither seeded in the fetcher nor scripted — and
    // the test passed, because the reactor DROPPED the sibling's in-flight
    // future when it paused at `wait`. The pause now drains in-flight
    // siblings through the completion handler, so an unfetchable sibling is
    // (correctly) a run failure rather than an invisible one.
    let graph = WorkflowGraphBuilder::new()
        .add_module("start", start_mod, None)
        .add_module("sibling", sibling_mod, None)
        .add_system_node("wait", SystemNodeKind::Wait { message: None })
        .add_module("after", after_mod, None)
        .edge("start", "wait")
        .edge("start", "sibling")
        .edge("wait", "after")
        .build()
        .expect("graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(start_mod, stub_artifact(start_mod))
            .with_module(sibling_mod, stub_artifact(sibling_mod))
            .with_module(after_mod, stub_artifact(after_mod)),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(start_mod, json!({"output": "start"}))
            .with_response(sibling_mod, json!({"output": "sibling"}))
            .with_response(after_mod, json!({"output": "after"})),
    );

    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("pause");
    let wait_id = engine
        .node_labels()
        .iter()
        .find_map(|(id, label)| (label == "wait").then_some(*id))
        .unwrap();
    let envelope = &ctx.results[&wait_id];
    assert_eq!(envelope["__waiting__"].as_bool(), Some(true));
    assert!(
        envelope.get("message").is_none(),
        "envelope unexpectedly carries `message`: {envelope}"
    );
}

/// A pause must not lose siblings that are already IN FLIGHT.
///
/// Shape:
///
/// ```text
///   a ─→ wait ─→ after
///   b ─→ c
///     ─→ d
/// ```
///
/// `a` and `b` are both roots and dispatch in the same pass. Whichever
/// completes first, the reactor reaches `wait` while a module future from
/// the OTHER branch is still in `executing` — dispatched (the job is on the
/// wire; here the `ScriptedDispatcher` has counted it) but not yet yielded.
/// Pre-fix the pause `return`ed with that future un-awaited: side effects
/// happened, the result was never committed, the checkpoint recorded the
/// node as never run, and the resume dispatched it AGAIN. The invariant
/// this pins: **every module the dispatcher was asked to run has its
/// result in the paused context**, and the resume re-runs none of them.
#[tokio::test]
async fn pause_commits_in_flight_siblings_instead_of_dropping_them() {
    let a_mod = Uuid::new_v4();
    let b_mod = Uuid::new_v4();
    let c_mod = Uuid::new_v4();
    let d_mod = Uuid::new_v4();
    let after_mod = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("a", a_mod, None)
        .add_module("b", b_mod, None)
        .add_module("c", c_mod, None)
        .add_module("d", d_mod, None)
        .add_system_node(
            "wait",
            SystemNodeKind::Wait {
                message: Some("hold".into()),
            },
        )
        .add_module("after", after_mod, None)
        .edge("a", "wait")
        .edge("wait", "after")
        .edge("b", "c")
        .edge("b", "d")
        .build()
        .expect("graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    for m in [a_mod, b_mod, c_mod, d_mod, after_mod] {
        fetcher = fetcher.with_module(m, stub_artifact(m));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(a_mod, json!({"output": "a"}))
            .with_response(b_mod, json!({"output": "b"}))
            .with_response(c_mod, json!({"output": "c"}))
            .with_response(d_mod, json!({"output": "d"}))
            .with_response(after_mod, json!({"output": "after"})),
    );

    let label_id = |engine: &ParallelWorkflowEngine, name: &str| -> Uuid {
        engine
            .node_labels()
            .iter()
            .find_map(|(id, label)| (label == name).then_some(*id))
            .unwrap_or_else(|| panic!("missing label {name}"))
    };

    let exec_id = Uuid::new_v4();
    let paused = engine
        .run_with_transport(dispatcher.clone(), None, exec_id)
        .await
        .expect("the run pauses rather than failing");
    assert!(paused.waiting);
    let wait_id = label_id(&engine, "wait");
    assert!(paused.results.contains_key(&wait_id));

    // The invariant: dispatched ⇒ committed. Which of b/c/d were dispatched
    // before the pause depends on completion order (both are legal); what is
    // NOT legal is a dispatched module whose result is missing.
    let mut dispatched_before_pause = 0;
    for (name, module) in [("a", a_mod), ("b", b_mod), ("c", c_mod), ("d", d_mod)] {
        let count = dispatcher.dispatch_count(module);
        assert!(
            count <= 1,
            "{name} dispatched {count} times before the pause"
        );
        if count == 1 {
            dispatched_before_pause += 1;
            assert!(
                paused.results.contains_key(&label_id(&engine, name)),
                "{name} was dispatched before the pause but its result was dropped: {:?}",
                paused.results.keys().collect::<Vec<_>>()
            );
        }
    }
    // `a` completed (it unblocked `wait`) and `b` was pushed in the same
    // pass as `a`, so at least those two were dispatched.
    assert!(dispatched_before_pause >= 2);
    assert_eq!(
        dispatcher.dispatch_count(after_mod),
        0,
        "nothing past the Wait runs before the resume"
    );

    // Resume from the paused snapshot: every previously-dispatched module
    // keeps a count of exactly 1 — the resume re-runs none of them.
    let mut seed: HashMap<Uuid, serde_json::Value> = paused.results.clone();
    seed.insert(wait_id, json!({"approved_by": "ops"}));
    let done = engine
        .run_with_seed_with_transport(dispatcher.clone(), None, seed, exec_id)
        .await
        .expect("resume completes");
    assert!(!done.waiting);
    for (name, module) in [
        ("a", a_mod),
        ("b", b_mod),
        ("c", c_mod),
        ("d", d_mod),
        ("after", after_mod),
    ] {
        assert_eq!(
            dispatcher.dispatch_count(module),
            1,
            "{name} must run exactly once across pause + resume"
        );
        assert!(done.results.contains_key(&label_id(&engine, name)));
    }
}
