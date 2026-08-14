//! Pipeline-chain dispatch is OFF on the production entry point — pinned
//! through that entry point, not through a convenience one.
//!
//! ## What this exists to stop
//!
//! `engine.rs` gated the chain optimisation on
//! `is_fresh_run = initial_results.is_empty()`. That expression describes the
//! shape of an argument; it does not state a decision, and the decision it
//! silently made was that chain dispatch is disabled for every workflow this
//! platform actually runs — because `run_with_trigger_input_transport` seeds
//! a synthetic `__trigger__` node, which makes the map non-empty, which the
//! gate read as "this is a resume". Nothing in the codebase said so. The gate
//! is now an explicit `ChainDispatch` parameter (see its docs in `engine.rs`);
//! these tests are what stops the value drifting back without anyone noticing.
//!
//! ## Why there is a CONTROL, and why it is the important half
//!
//! "`dispatch_chain` was called zero times" is a claim that passes for two
//! very different reasons: because the gate is off, or because the graph never
//! formed a chain in the first place. The second reading makes the test
//! vacuous — it would keep passing after someone enabled chain dispatch, which
//! is precisely the regression it is supposed to catch.
//!
//! So the assertions here are paired. Each control loads the same graph JSON as
//! its pin and runs it through `run_with_transport` — the one entry point that
//! passes `ChainDispatch::Enabled` — and requires a chain dispatch to happen.
//! If a control ever goes red, its pin has stopped meaning anything and must
//! not be trusted until the control is green again.
//!
//! BUT THE CONTROL DOES NOT RUN THE GRAPH THE PIN RUNS, and saying it did was
//! wrong in exactly the variable that made the first version of this pin
//! vacuous. `run_with_transport` never calls
//! `ensure_trigger_node_wired_to_roots`, so the control runs the **6-node**
//! graph while the pin runs a **7-node** one containing the synthetic
//! `__trigger__` — and whether the trigger absorbs the chains is precisely what
//! decides if the pin can fail at all. A control that differs from its pin in
//! the one dimension under test is not a control for that dimension.
//!
//! So the pin carries its OWN non-vacuity assertion rather than borrowing the
//! control's: after the run it re-derives `detect_linear_chains` on the graph
//! the pin ACTUALLY ran and requires two 3-node chains with no trigger in them.
//! That establishes in-test what was previously established only in a commit
//! message — the chains survived the filter on the pin's own graph, so zero
//! chain dispatches can only be the gate. (`the_synthetic_trigger_absorbs_the_
//! chain_it_is_wired_into` already does this at the bottom of the file; the pin
//! simply needed the same treatment.)
//!
//! ## The version of this file that could not fail, and why it was replaced
//!
//! The pin was first written against a single-root three-node chain, and it
//! passed. It would also have passed with the gate flipped to `Enabled`: the
//! synthetic trigger wires to the single root, becomes the only chain START,
//! and therefore lands INSIDE the sole detected chain — which the engine
//! discards because the trigger has no `module_id`. Zero chain dispatches,
//! gate irrelevant. That is a check that cannot fail for the reason it exists,
//! written inside the change whose thesis is that such checks are worthless.
//!
//! The pin now uses a TWO-root graph, where the trigger has out-degree 2, is
//! not a chain start, and is not absorbed — so both module-only chains survive
//! the filter and the gate is the only thing suppressing them. Flipping
//! `ChainDispatch::Disabled` to `Enabled` in the trigger entry point turns
//! `production_entrypoint_never_batches_chains` RED.
//!
//! ## What these tests deliberately do NOT do
//!
//! They do not enable chain dispatch, and they must not be read as groundwork
//! for doing so. `the_synthetic_trigger_absorbs_the_chain_it_is_wired_into`
//! demonstrates one of the two reasons a naive flip would not work (the
//! synthetic trigger disqualifies the chain that contains it). The other
//! reason is not expressible here: this file
//! exercises the engine's own scheduler with in-memory adapters, and the
//! second defect is that `engine_dispatch_pipeline.rs` has no `skip_condition`
//! handling at all, so a flip would DELIVER messages that a skip condition
//! exists to suppress. That is a live-workflow property; see `ChainDispatch`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::{detect_linear_chains, ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, NodeDispatcher, StepStatus, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

/// Records which dispatch API the scheduler chose, per node.
#[derive(Default)]
struct RouteRecordingDispatcher {
    /// Node ids handed to `dispatch` (the per-node path).
    single: Mutex<Vec<Uuid>>,
    /// One entry per `dispatch_chain` CALL, each holding that call's node ids.
    chained: Mutex<Vec<Vec<Uuid>>>,
}

impl RouteRecordingDispatcher {
    fn single_nodes(&self) -> Vec<Uuid> {
        self.single.lock().unwrap().clone()
    }
    fn chain_calls(&self) -> Vec<Vec<Uuid>> {
        self.chained.lock().unwrap().clone()
    }
}

#[async_trait]
impl NodeDispatcher for RouteRecordingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        self.single.lock().unwrap().push(job.node_id);
        Ok(DispatchResult {
            output: json!({"output": "ok"}),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        self.chained
            .lock()
            .unwrap()
            .push(request.steps.iter().map(|s| s.node_id).collect());
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

async fn engine_for(graph: serde_json::Value, ids: &[Uuid]) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    for id in ids {
        fetcher = fetcher.with_module(*id, stub_artifact(*id));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");
    engine
}

/// Three module nodes in a straight line — the canonical shape
/// `detect_linear_chains` is built to batch. Node id == module id because
/// `WorkflowGraphBuilder` derives a stable Uuid from a UUID-shaped label.
async fn linear_three_node_engine(ids: [Uuid; 3]) -> ParallelWorkflowEngine {
    let graph = WorkflowGraphBuilder::new()
        .add_module(ids[0].to_string(), ids[0], None)
        .add_module(ids[1].to_string(), ids[1], None)
        .add_module(ids[2].to_string(), ids[2], None)
        .edge(ids[0].to_string(), ids[1].to_string())
        .edge(ids[1].to_string(), ids[2].to_string())
        .build()
        .expect("graph builds");
    engine_for(graph, &ids).await
}

/// TWO independent 3-node chains — and the shape the PIN below must use.
///
/// Discovered while checking whether the pin could actually fail: on a
/// SINGLE-root graph it cannot. The synthetic trigger wires to the one root,
/// which makes the trigger the only chain start, which puts the trigger
/// INSIDE the sole detected chain, which the engine's `module_id.is_some()`
/// filter then discards — so `dispatch_chain` is never called on that graph
/// whether the gate says `Enabled` or `Disabled`. A pin built on it would
/// have kept passing after someone flipped the gate: a check that cannot fail
/// for the reason it exists, shipped inside the change whose whole thesis is
/// that such checks are worthless. (The single-root behaviour is real and
/// worth recording — `the_synthetic_trigger_absorbs_the_chain_it_is_wired_into`
/// keeps it — it is just not a gate test.)
///
/// With TWO roots the trigger has out-degree 2, so it is not a chain start
/// and is not swallowed into either chain; each root has in-degree 1 from a
/// parent with out-degree 2, so each root STARTS its own module-only chain.
/// Those chains survive the filter, and the gate is then the only thing
/// standing between this graph and a batched dispatch.
async fn two_chain_engine(ids: [Uuid; 6]) -> ParallelWorkflowEngine {
    let mut b = WorkflowGraphBuilder::new();
    for id in ids {
        b = b.add_module(id.to_string(), id, None);
    }
    let graph = b
        .edge(ids[0].to_string(), ids[1].to_string())
        .edge(ids[1].to_string(), ids[2].to_string())
        .edge(ids[3].to_string(), ids[4].to_string())
        .edge(ids[4].to_string(), ids[5].to_string())
        .build()
        .expect("graph builds");
    engine_for(graph, &ids).await
}

/// CONTROL. Without this the negative test below proves nothing: it would
/// pass just as happily against a graph that cannot form a chain at all.
///
/// `run_with_transport` is the only entry point that passes
/// `ChainDispatch::Enabled`, and no non-test caller in this workspace uses it.
#[tokio::test]
async fn control_linear_chain_is_batched_on_the_unseeded_entrypoint() {
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let engine = linear_three_node_engine(ids).await;
    let dispatcher = Arc::new(RouteRecordingDispatcher::default());

    engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect("run succeeds");

    let chain_calls = dispatcher.chain_calls();
    assert_eq!(
        chain_calls.len(),
        1,
        "CONTROL FAILED: this graph must batch into exactly one chain when the gate is \
         Enabled. Until this is green, `production_entrypoint_never_batches_chains` is \
         vacuous and proves nothing. chain calls: {chain_calls:?}"
    );
    assert_eq!(
        chain_calls[0].len(),
        3,
        "the chain must span all three module nodes; got {:?}",
        chain_calls[0]
    );
    assert!(
        dispatcher.single_nodes().is_empty(),
        "a batched chain must not ALSO dispatch its nodes individually; got {:?}",
        dispatcher.single_nodes()
    );
}

/// SECOND CONTROL, on the graph the pin actually uses. Establishes that this
/// two-root graph forms module-only chains that SURVIVE the filter — so when
/// the pin below sees zero chain dispatches, the gate is the only thing that
/// can be responsible.
#[tokio::test]
async fn control_two_root_graph_batches_two_chains_when_enabled() {
    let ids: [Uuid; 6] = std::array::from_fn(|_| Uuid::new_v4());
    let engine = two_chain_engine(ids).await;
    let dispatcher = Arc::new(RouteRecordingDispatcher::default());

    engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect("run succeeds");

    let chain_calls = dispatcher.chain_calls();
    assert_eq!(
        chain_calls.len(),
        2,
        "CONTROL FAILED: the two-root graph must batch into two chains when the gate is \
         Enabled. Until this is green, `production_entrypoint_never_batches_chains` cannot \
         distinguish 'the gate is off' from 'this graph never forms a chain'. got: \
         {chain_calls:?}"
    );
    for c in &chain_calls {
        assert_eq!(
            c.len(),
            3,
            "each chain must span its three nodes; got {c:?}"
        );
    }
}

/// THE PIN. The production entry point — the one every trigger, schedule,
/// retry, replay, webhook and continuation reaches the engine through —
/// dispatches node by node and never batches.
///
/// Uses the TWO-ROOT graph deliberately. On a single-root graph this
/// assertion is unfalsifiable (see `two_chain_engine`'s docs): the synthetic
/// trigger absorbs the only chain and the filter discards it, so zero chain
/// dispatches happen regardless of the gate. Here the chains survive the
/// filter, so flipping `ChainDispatch::Disabled` to `Enabled` in
/// `run_with_trigger_input_transport` turns this test RED — which is the
/// entire point of it existing.
///
/// This asserts CURRENT behaviour on purpose. It is not an endorsement: see
/// this file's header and `ChainDispatch`'s docs for why turning batching on
/// is a two-defect fix and an operator decision, not a value change.
#[tokio::test]
async fn production_entrypoint_never_batches_chains() {
    let ids: [Uuid; 6] = std::array::from_fn(|_| Uuid::new_v4());
    let mut engine = two_chain_engine(ids).await;
    let dispatcher = Arc::new(RouteRecordingDispatcher::default());

    engine
        .run_with_trigger_input_transport(
            dispatcher.clone(),
            None,
            json!({ "event": "http.POST" }),
            Uuid::new_v4(),
        )
        .await
        .expect("run succeeds");

    assert!(
        dispatcher.chain_calls().is_empty(),
        "run_with_trigger_input_transport must NOT batch chains — every production run \
         reaches the engine this way, and `engine_dispatch_pipeline.rs` has no \
         skip_condition handling, so batching would deliver suppressed sends. \
         got: {:?}",
        dispatcher.chain_calls()
    );

    let mut single = dispatcher.single_nodes();
    single.sort();
    let mut expected = ids.to_vec();
    expected.sort();
    assert_eq!(
        single, expected,
        "all six nodes must have been dispatched individually"
    );

    // NON-VACUITY, ON THE GRAPH THIS TEST ACTUALLY RAN.
    //
    // The control above cannot establish this: it runs through
    // `run_with_transport`, which never installs the synthetic `__trigger__`,
    // so it exercises the 6-node graph while this test's engine now holds a
    // 7-node one. The trigger is the whole variable — on a single-root graph it
    // absorbs the only chain and the engine's `module_id.is_some()` filter
    // discards it, which is what made the FIRST version of this pin unable to
    // fail. Asserting it here, on the post-run graph, is what stops that
    // regressing quietly; previously it lived only in a commit message.
    let chains = detect_linear_chains(engine.graph());
    assert_eq!(
        chains.len(),
        2,
        "VACUITY GUARD: the graph this pin ran must still yield two chains AFTER the \
         synthetic trigger was wired in. If it does not, zero chain dispatches proves \
         nothing about the gate. got: {chains:?}"
    );
    for c in &chains {
        assert_eq!(
            c.len(),
            3,
            "each surviving chain must span its three module nodes, i.e. NOT have absorbed \
             the trigger; got {c:?}"
        );
        let has_trigger = c.iter().any(|&idx| {
            let node_id = engine.graph()[idx];
            engine
                .node_labels()
                .get(&node_id)
                .map(|l| l.as_str() == talos_workflow_engine_core::reserved_keys::TRIGGER)
                .unwrap_or(false)
        });
        assert!(
            !has_trigger,
            "a chain containing the synthetic trigger is dropped by the engine's module_id \
             filter, which would make this pin vacuous; got {c:?}"
        );
    }
}

/// The MECHANISM behind one of the two blockers, demonstrated rather than
/// asserted in prose: even with the gate flipped to `Enabled`, a graph
/// carrying the synthetic `__trigger__` node yields no usable chain.
///
/// `detect_linear_chains` walks from a node with in-degree 0. Once the trigger
/// is wired to the root, the root's in-degree is 1 and its parent's out-degree
/// is 1, so the root is no longer a chain START — the only chain found begins
/// at the trigger and therefore CONTAINS it. The engine's filter then drops
/// any chain holding a node with `module_id == None`, which the trigger is.
/// Net: flipping the flag recovers nothing for a single-root graph.
#[tokio::test]
async fn the_synthetic_trigger_absorbs_the_chain_it_is_wired_into() {
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let mut engine = linear_three_node_engine(ids).await;

    // Before the trigger exists, the three modules are one clean chain.
    let before = detect_linear_chains(engine.graph());
    assert_eq!(
        before.len(),
        1,
        "precondition: the bare graph is one chain; got {before:?}"
    );
    assert_eq!(before[0].len(), 3, "…spanning all three nodes");

    // Running through the trigger entry point installs the synthetic node.
    let dispatcher = Arc::new(RouteRecordingDispatcher::default());
    engine
        .run_with_trigger_input_transport(dispatcher, None, json!({}), Uuid::new_v4())
        .await
        .expect("run succeeds");

    let after = detect_linear_chains(engine.graph());
    // Still one chain, but it now starts at the trigger and is four long —
    // and the trigger has no module, so the engine's filter discards it whole.
    assert_eq!(
        after.len(),
        1,
        "the trigger does not split the chain, it JOINS it; got {after:?}"
    );
    assert_eq!(
        after[0].len(),
        4,
        "the detected chain must now include the synthetic trigger, which is why \
         the engine's module_id filter drops it entirely; got {:?}",
        after[0]
    );
    let trigger_is_in_the_chain = after[0].iter().any(|&idx| {
        let node_id = engine.graph()[idx];
        engine
            .node_labels()
            .get(&node_id)
            .map(|l| l.as_str() == talos_workflow_engine_core::reserved_keys::TRIGGER)
            .unwrap_or(false)
    });
    assert!(
        trigger_is_in_the_chain,
        "the point of this test is that the trigger is INSIDE the only detected chain"
    );
}
