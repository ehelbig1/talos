//! `CancellationToken` plumbing across both APIs:
//!
//! * Per-call: `run_with_transport_cancellable` /
//!   `run_with_seed_with_transport_cancellable` take a token as a
//!   parameter.
//! * Engine-level: `set_cancellation_token` persists a token on the
//!   engine that the non-`_cancellable` run methods consult, and
//!   that propagates through `AdapterSet` to sub-workflow loops.
//!
//! The contract:
//!
//! 1. Cancelling the token returns `WorkflowEngineError::Cancelled`
//!    promptly — the engine doesn't wait for in-flight dispatches to
//!    drain.
//! 2. A token cancelled BEFORE the run starts also produces
//!    `Cancelled` (no work attempted).
//! 3. A token that is never cancelled doesn't change behaviour —
//!    the workflow runs to completion as on the non-cancellable
//!    path.
//! 4. The seeded resume path honours the same contract.
//! 5. The setter-provided token is inherited by sub-workflows
//!    through `AdapterSet`.
//!
//! In-flight worker abort is explicitly out of scope — the engine
//! has no out-of-band channel to a worker pool. See the
//! `Cancelled` variant docstring for the supported model.

use std::sync::Arc;
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

/// Dispatcher that parks for `delay` before returning success — long
/// enough to let a cancellation race the dispatch.
struct ParkingDispatcher {
    delay: Duration,
}

#[async_trait]
impl NodeDispatcher for ParkingDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        tokio::time::sleep(self.delay).await;
        Ok(DispatchResult {
            output: json!({"output": "slow"}),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        tokio::time::sleep(self.delay).await;
        let steps: Vec<ChainStepResult> = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: json!({"output": "slow"}),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: json!({"output": "slow"}),
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

/// Fan-out graph (root → {a, b}) — keeps every node on the per-node
/// dispatch path, same shape as the `workflow_timeout` tests.
fn build_slow_graph() -> (serde_json::Value, Uuid, Uuid, Uuid) {
    let root = Uuid::new_v4();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let g = WorkflowGraphBuilder::new()
        .add_module("root", root, None)
        .add_module("a", a, None)
        .add_module("b", b, None)
        .edge("root", "a")
        .edge("root", "b")
        .build()
        .expect("graph builds");
    (g, root, a, b)
}

fn engine_for(root: Uuid, a: Uuid, b: Uuid) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(root, stub_artifact(root))
            .with_module(a, stub_artifact(a))
            .with_module(b, stub_artifact(b)),
    ));
    // 30 s wall-clock cap so cancellation, not the timeout, is the
    // signal under test. Without this the workflow_timeout fail-safe
    // could trip first on a slow CI runner.
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_during_run_returns_cancelled_error() {
    let (graph_json, root, a, b) = build_slow_graph();
    let mut engine = engine_for(root, a, b);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("load");

    // Each dispatch sleeps 10 s; the run would otherwise take >10 s.
    let dispatcher = Arc::new(ParkingDispatcher {
        delay: Duration::from_secs(10),
    });
    let cancel = CancellationToken::new();

    // Trigger cancel from a sibling task ~50 ms in. The engine must
    // observe it before the dispatch returns.
    let cancel_trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel_trigger.cancel();
    });

    let started = std::time::Instant::now();
    let err = engine
        .run_with_transport_cancellable(dispatcher, None, Uuid::new_v4(), cancel)
        .await
        .expect_err("must fail with Cancelled");
    let elapsed = started.elapsed();

    assert!(
        matches!(err, WorkflowEngineError::Cancelled),
        "expected Cancelled, got: {err:?}"
    );
    // Should return well under the 10 s dispatch sleep — proves the
    // engine bailed promptly rather than waiting for in-flight work.
    assert!(
        elapsed < Duration::from_secs(2),
        "cancellation took {elapsed:?}, expected < 2s"
    );
}

#[tokio::test]
async fn pre_cancelled_token_returns_cancelled_immediately() {
    // Cancellation that's already triggered before the run starts
    // must be honoured — no dispatch attempted.
    let (graph_json, root, a, b) = build_slow_graph();
    let mut engine = engine_for(root, a, b);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(ParkingDispatcher {
        delay: Duration::from_secs(10),
    });
    let cancel = CancellationToken::new();
    cancel.cancel();

    let err = engine
        .run_with_transport_cancellable(dispatcher, None, Uuid::new_v4(), cancel)
        .await
        .expect_err("pre-cancelled token must surface Cancelled");
    assert!(matches!(err, WorkflowEngineError::Cancelled));
}

#[tokio::test]
async fn never_cancelled_token_does_not_change_behaviour() {
    // Sanity: a token that's never cancelled is a no-op. The
    // workflow runs to completion identically to the non-cancellable
    // entry point.
    let (graph_json, root, a, b) = build_slow_graph();
    let mut engine = engine_for(root, a, b);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(root, json!({"output": "root"}))
            .with_response(a, json!({"output": "a"}))
            .with_response(b, json!({"output": "b"})),
    );
    let cancel = CancellationToken::new(); // never .cancel()'d
    let ctx = engine
        .run_with_transport_cancellable(dispatcher, None, Uuid::new_v4(), cancel)
        .await
        .expect("must complete");
    assert_eq!(ctx.results.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_via_setter_propagates_through_run_with_transport() {
    // The set_cancellation_token() setter is the lower-ceremony API
    // for embedders that wire one cancel signal per run lifecycle
    // (typical pattern: graceful-shutdown handler triggers cancel,
    // engine reactor sees it on the next dispatch boundary). This
    // test locks in that the non-`_cancellable` run methods consult
    // the setter — without it, every embedder has to switch to the
    // `_cancellable` variants explicitly.
    let (graph_json, root, a, b) = build_slow_graph();
    let mut engine = engine_for(root, a, b);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("load");

    let cancel = CancellationToken::new();
    engine.set_cancellation_token(Some(cancel.clone()));

    let dispatcher = Arc::new(ParkingDispatcher {
        delay: Duration::from_secs(10),
    });

    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });

    let started = std::time::Instant::now();
    let err = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("setter-wired cancel must trip run_with_transport");
    let elapsed = started.elapsed();

    assert!(matches!(err, WorkflowEngineError::Cancelled));
    assert!(
        elapsed < Duration::from_secs(2),
        "cancellation took {elapsed:?}, expected < 2s"
    );
}

#[tokio::test]
async fn cancel_token_setter_round_trips_and_propagates_through_adapter_set() {
    // Two separate properties:
    //   1. The setter actually persists the token (accessor returns
    //      what we put in).
    //   2. AdapterSet carries it across — sub-workflow loops hydrate
    //      a fresh sub-engine from `self.adapter_set()` and the
    //      cancel signal MUST reach them, otherwise a parent cancel
    //      stops the parent reactor but lets sub-workflows keep
    //      dispatching. That's the documented contract.
    use talos_workflow_engine::ParallelWorkflowEngine;

    let mut engine = ParallelWorkflowEngine::new();
    assert!(engine.cancellation_token().is_none());

    let token = CancellationToken::new();
    engine.set_cancellation_token(Some(token.clone()));
    assert!(engine.cancellation_token().is_some());

    // Hydrate a sub-engine the way agent-loop dispatch does. The
    // cancel must ride along.
    let cloned = engine.adapter_set().into_engine();
    let inherited = cloned.cancellation_token().expect("must inherit");

    // Sanity: the inherited token shares the same cancel state as
    // the original (CancellationToken is internally an Arc).
    assert!(!inherited.is_cancelled());
    token.cancel();
    assert!(
        inherited.is_cancelled(),
        "child token should observe parent cancel"
    );

    // Clearing on the parent goes through too.
    let mut engine2 = ParallelWorkflowEngine::new();
    engine2.set_cancellation_token(Some(CancellationToken::new()));
    engine2.set_cancellation_token(None);
    assert!(engine2.cancellation_token().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_on_seeded_resume_path() {
    // Seeded resume must honour cancellation the same way as the
    // fresh path. Without this regression guard, an embedder cancelling
    // a long-running checkpoint resume would silently keep dispatching.
    let (graph_json, root, a, b) = build_slow_graph();
    let mut engine = engine_for(root, a, b);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(ParkingDispatcher {
        delay: Duration::from_secs(10),
    });
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });

    let started = std::time::Instant::now();
    let err = engine
        .run_with_seed_with_transport_cancellable(
            dispatcher,
            None,
            std::collections::HashMap::new(),
            Uuid::new_v4(),
            cancel,
        )
        .await
        .expect_err("seeded path must honour cancellation");
    assert!(matches!(err, WorkflowEngineError::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(2));
}
