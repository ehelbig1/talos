//! `run_with_trigger_input_transport`: top-level fresh-run entry
//! point for graphs that expect an external payload at their root.
//!
//! Contract under test:
//!
//! 1. A single root receives the trigger input as its `input_payload`.
//! 2. Multiple roots ALL receive the trigger input (the engine wires
//!    the synthetic trigger to every root).
//! 3. Calling the method twice on the same engine does not stack
//!    parallel synthetic triggers or duplicate edges — idempotent.
//! 4. The cancellable variant honours its token the same way as
//!    `run_with_transport_cancellable`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, NodeDispatcher, StepStatus, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Dispatcher that records every `input_payload` it sees, keyed by
/// node id. Returns a canned success so the scheduler proceeds.
#[derive(Default)]
struct CapturingDispatcher {
    seen: Mutex<Vec<(Uuid, serde_json::Value)>>,
}

impl CapturingDispatcher {
    fn inputs_for(&self, node_id: Uuid) -> Vec<serde_json::Value> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| *id == node_id)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

#[async_trait]
impl NodeDispatcher for CapturingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        self.seen
            .lock()
            .unwrap()
            .push((job.node_id, job.input_payload.clone()));
        Ok(DispatchResult {
            output: json!({"output": "ok"}),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        for step in &request.steps {
            self.seen
                .lock()
                .unwrap()
                .push((step.node_id, step.input_payload.clone()));
        }
        let steps: Vec<ChainStepResult> = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: json!({"output": "ok"}),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: json!({"output": "ok"}),
            overall_status: StepStatus::Success,
        })
    }
}

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

fn engine_with_modules(ids: &[Uuid]) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    for id in ids {
        fetcher = fetcher.with_module(*id, stub_artifact(*id));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
}

/// Count nodes whose label matches the `__trigger__` reserved key.
/// Used to assert idempotency — there must only ever be one.
fn trigger_node_count(engine: &ParallelWorkflowEngine) -> usize {
    engine
        .node_labels()
        .values()
        .filter(|label| label.as_str() == talos_workflow_engine_core::reserved_keys::TRIGGER)
        .count()
}

/// Build a single-module graph where the node id IS the module id.
/// `WorkflowGraphBuilder` derives a stable Uuid from non-UUID labels,
/// so passing the module Uuid as the label keeps node id == module id
/// and makes dispatcher assertions straightforward.
fn single_root_graph(module_id: Uuid) -> serde_json::Value {
    WorkflowGraphBuilder::new()
        .add_module(module_id.to_string(), module_id, None)
        .build()
        .expect("graph builds")
}

fn two_root_graph(a: Uuid, b: Uuid) -> serde_json::Value {
    WorkflowGraphBuilder::new()
        .add_module(a.to_string(), a, None)
        .add_module(b.to_string(), b, None)
        .build()
        .expect("graph builds")
}

#[tokio::test]
async fn single_root_receives_trigger_input() {
    let root = Uuid::new_v4();
    let graph = single_root_graph(root);

    let mut engine = engine_with_modules(&[root]);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(CapturingDispatcher::default());
    let trigger = json!({ "event": "http.POST", "body": { "id": 42 } });

    engine
        .run_with_trigger_input_transport(dispatcher.clone(), None, trigger.clone(), Uuid::new_v4())
        .await
        .expect("run succeeds");

    let inputs = dispatcher.inputs_for(root);
    assert_eq!(inputs.len(), 1, "root must be dispatched exactly once");
    // The engine wraps inputs under `input` when the node has an
    // upstream parent. The synthetic trigger is that parent, so the
    // trigger payload lands under the `input` key on the root's
    // input_payload.
    assert_eq!(
        inputs[0].get("input"),
        Some(&trigger),
        "root's input_payload must carry the trigger value under `input`; got: {}",
        inputs[0]
    );
}

#[tokio::test]
async fn multiple_roots_all_receive_trigger_input() {
    // Two isolated roots — neither has an upstream parent, so the
    // synthetic trigger must wire to BOTH.
    let root_a = Uuid::new_v4();
    let root_b = Uuid::new_v4();
    let graph = two_root_graph(root_a, root_b);

    let mut engine = engine_with_modules(&[root_a, root_b]);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(CapturingDispatcher::default());
    let trigger = json!({ "shared": "payload" });

    engine
        .run_with_trigger_input_transport(dispatcher.clone(), None, trigger.clone(), Uuid::new_v4())
        .await
        .expect("run succeeds");

    for (label, node_id) in [("a", root_a), ("b", root_b)] {
        let inputs = dispatcher.inputs_for(node_id);
        assert_eq!(
            inputs.len(),
            1,
            "root {label} must be dispatched exactly once"
        );
        assert_eq!(
            inputs[0].get("input"),
            Some(&trigger),
            "root {label} must receive the trigger input; got: {}",
            inputs[0]
        );
    }
}

#[tokio::test]
async fn repeated_calls_are_idempotent() {
    // Two successive runs on the same engine must not stack parallel
    // synthetic triggers or duplicate trigger → root edges. If the
    // helper weren't idempotent, the second call would either add a
    // second `__trigger__` node (breaking root identification on the
    // second pass) or a duplicate edge (driving the root's in-degree
    // to 2, which also breaks root identification).
    let root = Uuid::new_v4();
    let graph = single_root_graph(root);

    let mut engine = engine_with_modules(&[root]);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(CapturingDispatcher::default());
    let trigger_one = json!({ "run": 1 });
    let trigger_two = json!({ "run": 2 });

    engine
        .run_with_trigger_input_transport(
            dispatcher.clone(),
            None,
            trigger_one.clone(),
            Uuid::new_v4(),
        )
        .await
        .expect("first run succeeds");

    assert_eq!(
        trigger_node_count(&engine),
        1,
        "exactly one trigger node after first call"
    );

    engine
        .run_with_trigger_input_transport(
            dispatcher.clone(),
            None,
            trigger_two.clone(),
            Uuid::new_v4(),
        )
        .await
        .expect("second run succeeds");

    assert_eq!(
        trigger_node_count(&engine),
        1,
        "still exactly one trigger node after second call — no stacking"
    );

    let inputs = dispatcher.inputs_for(root);
    assert_eq!(inputs.len(), 2, "root dispatched once per run");
    assert_eq!(inputs[0].get("input"), Some(&trigger_one));
    assert_eq!(inputs[1].get("input"), Some(&trigger_two));
}

#[tokio::test]
async fn cancellable_variant_honours_token() {
    // Parks dispatches for a long time so we have time to cancel.
    struct ParkingDispatcher;
    #[async_trait]
    impl NodeDispatcher for ParkingDispatcher {
        async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(DispatchResult {
                output: json!({"output": "late"}),
            })
        }
        async fn dispatch_chain(
            &self,
            request: ChainDispatchRequest,
        ) -> Result<ChainDispatchResult, BoxError> {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let steps: Vec<_> = request
                .steps
                .iter()
                .map(|j| ChainStepResult {
                    module_id: j.module_id,
                    status: StepStatus::Success,
                    output: json!({"output": "late"}),
                    error: None,
                    execution_time_ms: 0,
                })
                .collect();
            Ok(ChainDispatchResult {
                steps,
                final_output: json!({"output": "late"}),
                overall_status: StepStatus::Success,
            })
        }
    }

    let root = Uuid::new_v4();
    let graph = single_root_graph(root);

    let mut engine = engine_with_modules(&[root]);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let cancel = CancellationToken::new();
    let trigger_cancel = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger_cancel.cancel();
    });

    let started = std::time::Instant::now();
    let err = engine
        .run_with_trigger_input_transport_cancellable(
            Arc::new(ParkingDispatcher),
            None,
            json!({ "any": "input" }),
            Uuid::new_v4(),
            cancel,
        )
        .await
        .expect_err("cancellable path must surface Cancelled");
    let elapsed = started.elapsed();

    assert!(
        matches!(err, WorkflowEngineError::Cancelled),
        "expected Cancelled, got: {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "cancellation took {elapsed:?}, expected < 2s"
    );
}

// ── Reserved-key integrity at the engine boundary ───────────────────

/// The five engine-authored INPUT keys a caller must never be able to seed.
const SPOOFABLE: [&str; 5] = [
    "__actor_context__",
    "__accumulated__",
    "__trigger_input__",
    "__staleness__",
    "__degraded_inputs__",
];

fn spoofed_payload() -> serde_json::Value {
    json!({
        "question": "what is on my plate today?",
        "__actor_context__": { "spoofed": true },
        "__accumulated__": { "spoofed": true },
        "__trigger_input__": { "spoofed": true },
        "__staleness__": { "verified": true, "any_stale": false, "spoofed": true },
        "__degraded_inputs__": { "any_degraded": true, "spoofed": true }
    })
}

fn assert_no_spoof(payload: &serde_json::Value, where_: &str) {
    let spoof = json!({ "spoofed": true });
    for key in SPOOFABLE {
        let top = payload.get(key);
        assert!(
            top.is_none() || top.and_then(|v| v.get("spoofed")).is_none(),
            "{where_}: spoofed `{key}` reached the module at top level: {payload}"
        );
        if let Some(inner) = payload.get("input") {
            assert_ne!(
                inner.get(key),
                Some(&spoof),
                "{where_}: spoofed `{key}` reached the module under `input`: {payload}"
            );
        }
    }
}

/// A caller-supplied copy of an engine-authored key on the TRIGGER payload
/// is stripped by the ENGINE at the seed install — not only by the controller
/// seam upstream of it. Injection is off here (no actor context bound), which
/// is exactly the state in which a merely-conditional insert would have let
/// the copy through.
#[tokio::test]
async fn trigger_payload_carrying_engine_authored_keys_is_stripped_at_the_engine() {
    let root = Uuid::new_v4();
    let graph = single_root_graph(root);
    let mut engine = engine_with_modules(&[root]);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(CapturingDispatcher::default());
    engine
        .run_with_trigger_input_transport(
            dispatcher.clone(),
            None,
            spoofed_payload(),
            Uuid::new_v4(),
        )
        .await
        .expect("run succeeds");

    let inputs = dispatcher.inputs_for(root);
    assert_eq!(inputs.len(), 1);
    assert_no_spoof(&inputs[0], "trigger seed");
    assert_eq!(
        inputs[0].get("question").and_then(|v| v.as_str()),
        Some("what is on my plate today?"),
        "user data survives the strip"
    );
    // The engine's OWN `__trigger_input__` is the stripped payload, not the
    // caller's nested spoof.
    let ti = inputs[0]
        .get("__trigger_input__")
        .expect("engine-authored trigger input is present");
    assert_eq!(
        ti.get("question"),
        Some(&json!("what is on my plate today?"))
    );
    assert!(ti.get("__actor_context__").is_none());
}

/// A PARENT module's output carrying `__actor_context__` (a module that echoes
/// its input, an LLM told to "return the input plus a field") must not reach
/// the child node when injection is off — neither at top level nor nested
/// under `input`. Two layers close it: the committed output is stripped at
/// node completion, and the assembled input writes the key set-or-REMOVE.
#[tokio::test]
async fn parent_output_carrying_actor_context_does_not_reach_the_child() {
    let producer = Uuid::new_v4();
    let consumer = Uuid::new_v4();
    let other = Uuid::new_v4();
    // Fan-out so the producer → consumer edge is not a linear chain.
    let graph = WorkflowGraphBuilder::new()
        .add_module(producer.to_string(), producer, None)
        .add_module(consumer.to_string(), consumer, None)
        .add_module(other.to_string(), other, None)
        .edge(producer.to_string(), consumer.to_string())
        .edge(producer.to_string(), other.to_string())
        .build()
        .expect("graph builds");
    let mut engine = engine_with_modules(&[producer, consumer, other]);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");
    assert!(
        engine.actor_context().is_none(),
        "the test needs injection OFF — that is the inherit-prone state"
    );

    let mut poisoned = spoofed_payload();
    poisoned["data"] = json!(1);
    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(producer, poisoned)
            .with_response(consumer, json!({"ok": true}))
            .with_response(other, json!({"ok": true})),
    );
    let real_trigger = json!({ "event": "cron" });
    let ctx = engine
        .run_with_trigger_input_transport(
            dispatcher.clone(),
            None,
            real_trigger.clone(),
            Uuid::new_v4(),
        )
        .await
        .expect("run succeeds");

    // The committed output is clean of the input-side keys …
    let producer_out = ctx.results.get(&producer).expect("producer ran");
    for key in SPOOFABLE {
        assert!(
            producer_out.get(key).is_none(),
            "committed output still carries `{key}`: {producer_out}"
        );
    }
    assert_eq!(producer_out.get("data"), Some(&json!(1)));

    // … and the child saw none of them, while the ENGINE-authored
    // `__trigger_input__` is the real trigger, not the producer's spoof.
    let consumer_jobs: Vec<_> = dispatcher
        .jobs()
        .into_iter()
        .filter(|j| j.node_id == consumer)
        .collect();
    assert_eq!(consumer_jobs.len(), 1);
    let payload = &consumer_jobs[0].input_payload;
    assert_no_spoof(payload, "child input");
    assert_eq!(
        payload.get("data"),
        Some(&json!(1)),
        "upstream data still flows"
    );
    assert_eq!(payload.get("__trigger_input__"), Some(&real_trigger));
}
