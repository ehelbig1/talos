//! The four dispatch kinds RFC 0012 P2 added have a REACTOR-DRIVEN test —
//! RFC 0012 P3.
//!
//! P2 recorded, as a measured fact rather than a hypothetical, that deleting
//! the `ChildRunReporter::record` call at the tail of
//! `run_dispatched_subworkflow` left every `talos-workflow-engine` unit test
//! and both ledger DB binaries GREEN, and that the agent-loop body's
//! per-iteration record was in the same position. Neither function is public
//! and the loop body sits inside a `tokio::time::timeout`'d `async move`, so
//! observing either needs a full reactor run over a graph carrying one of
//! those nodes — which the P1 harness does not build.
//!
//! This file builds it. `run_with_transport` is the real reactor entry point
//! (the same one `system_node_failure_routing.rs` uses); the recorder is a
//! capturing `ChildRunRecorder`, because there is no in-memory impl anywhere in
//! the workspace and a DB is not what is under test here — the question is
//! whether the reactor reaches the write site at all, and with what.
//!
//! What is NOT covered, stated rather than implied: this asserts the RECORD the
//! engine hands to the recorder, not the row Postgres ends up with. The
//! INSERT, its sanitisation and its RLS policy are `child_run_ledger_tests`'
//! job, and that binary drives the P1 chokepoint against a real database.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use uuid::Uuid;

use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, ChildDispatchKind,
    ChildRunRecord, ChildRunRecorder, ChildRunStatus, DispatchJob, DispatchResult, NodeDispatcher,
    StepStatus, SystemNodeKind, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};

// ── harness ─────────────────────────────────────────────────────────────────

/// The only `ChildRunRecorder` a test can assert on: the workspace has exactly
/// one impl (`PostgresChildRunRecorder`) and test-utils has none.
#[derive(Default)]
struct CapturingRecorder(Mutex<Vec<ChildRunRecord>>);

impl CapturingRecorder {
    fn rows(&self) -> Vec<ChildRunRecord> {
        self.0.lock().expect("recorder lock").clone()
    }
    fn of_kind(&self, kind: ChildDispatchKind) -> Vec<ChildRunRecord> {
        self.rows()
            .into_iter()
            .filter(|r| r.dispatch_kind == kind)
            .collect()
    }
}

#[async_trait]
impl ChildRunRecorder for CapturingRecorder {
    async fn record(&self, record: ChildRunRecord) {
        self.0.lock().expect("recorder lock").push(record);
    }
}

/// One fixed output for every module dispatch, so the child's collapsed value
/// — and therefore the agent loop's termination — is entirely under the test's
/// control.
struct FixedOutputDispatcher(serde_json::Value);

#[async_trait]
impl NodeDispatcher for FixedOutputDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult {
            output: self.0.clone(),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        let steps: Vec<ChainStepResult> = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: self.0.clone(),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: self.0.clone(),
            overall_status: StepStatus::Success,
        })
    }
}

/// A graph store keyed by workflow id, plus a capability index — the
/// `capability_dispatch` handler resolves through `resolve_by_capabilities`,
/// so a store that serves one graph for every id cannot exercise it.
#[derive(Default)]
struct KeyedGraphStore {
    graphs: HashMap<Uuid, serde_json::Value>,
    by_capability: HashMap<Vec<String>, Uuid>,
}

impl KeyedGraphStore {
    fn with_graph(mut self, id: Uuid, graph: serde_json::Value) -> Self {
        self.graphs.insert(id, graph);
        self
    }
    fn with_capabilities(mut self, caps: Vec<String>, id: Uuid) -> Self {
        self.by_capability.insert(caps, id);
        self
    }
}

#[async_trait]
impl talos_workflow_engine_core::WorkflowGraphStore for KeyedGraphStore {
    async fn get_graph(
        &self,
        id: Uuid,
        _user: Uuid,
    ) -> Result<Option<serde_json::Value>, BoxError> {
        Ok(self.graphs.get(&id).cloned())
    }
    async fn get_graphs(
        &self,
        ids: &[Uuid],
        _user: Uuid,
    ) -> Result<HashMap<Uuid, serde_json::Value>, BoxError> {
        Ok(ids
            .iter()
            .filter_map(|id| self.graphs.get(id).map(|g| (*id, g.clone())))
            .collect())
    }
    async fn resolve_by_capabilities(
        &self,
        capabilities: &[String],
        _user: Uuid,
    ) -> Result<Option<(Uuid, String)>, BoxError> {
        Ok(self
            .by_capability
            .get(capabilities)
            .map(|id| (*id, "cap-child".to_string())))
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

/// A one-module child: the single terminal node means the engine collapses the
/// child's output to that module's value verbatim.
fn one_module_graph(module_id: Uuid) -> serde_json::Value {
    WorkflowGraphBuilder::new()
        .add_module(module_id.to_string(), module_id, None)
        .build()
        .expect("child graph builds")
}

struct Rig {
    engine: ParallelWorkflowEngine,
    recorder: Arc<CapturingRecorder>,
    parent_workflow: Uuid,
    user: Uuid,
}

/// `ChildRunReporter::record` is a silent no-op unless a recorder is set, the
/// origin is a tracked node, AND `workflow_id` is `Some` — so a rig that
/// forgot `set_workflow_id` would assert on an empty vec and prove nothing.
fn rig(
    parent_graph: &serde_json::Value,
    store: KeyedGraphStore,
    module_id: Uuid,
    out: serde_json::Value,
) -> Rig {
    let recorder = Arc::new(CapturingRecorder::default());
    let user = Uuid::new_v4();
    let parent_workflow = Uuid::new_v4();
    let mut engine = minimal_engine();
    engine.set_user_id(user);
    engine.set_workflow_id(parent_workflow);
    engine.set_child_run_recorder(recorder.clone());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module_id, stub_artifact(module_id)),
    ));
    engine.set_graph_store(Arc::new(store));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    futures::executor::block_on(
        engine.load_graph_from_json(&serde_json::to_string(parent_graph).unwrap()),
    )
    .expect("parent graph loads");
    let _ = out;
    Rig {
        engine,
        recorder,
        parent_workflow,
        user,
    }
}

async fn run(rig: &mut Rig, out: serde_json::Value) -> Uuid {
    let execution_id = Uuid::new_v4();
    let _ = rig
        .engine
        .run_with_transport(Arc::new(FixedOutputDispatcher(out)), None, execution_id)
        .await;
    execution_id
}

// ── C1: `dispatch` ──────────────────────────────────────────────────────────

/// A `dispatch` node's child run reaches the ledger.
///
/// MUTATION that turns it red (RFC 0012 P2's own M8): delete the
/// `reporter.record(..)` call at the tail of `run_dispatched_subworkflow`.
#[tokio::test]
async fn a_dispatch_node_records_one_child_run() {
    let module_id = Uuid::new_v4();
    let child_wf = Uuid::new_v4();
    let parent_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "dispatch_node",
            SystemNodeKind::DynamicDispatch {
                // A Rhai string literal, so no name resolution is involved.
                dispatch_expression: format!("\"{child_wf}\""),
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");
    let store = KeyedGraphStore::default().with_graph(child_wf, one_module_graph(module_id));
    let mut r = rig(&parent_graph, store, module_id, json!({"ok": true}));
    let execution_id = run(&mut r, json!({"ok": true})).await;

    let rows = r.recorder.of_kind(ChildDispatchKind::Dispatch);
    assert_eq!(
        rows.len(),
        1,
        "one dispatch, one row: {:?}",
        r.recorder.rows()
    );
    let row = &rows[0];
    assert_eq!(row.child_workflow_id, child_wf);
    assert_eq!(row.parent_execution_id, execution_id);
    assert_eq!(row.parent_workflow_id, r.parent_workflow);
    assert_eq!(row.parent_node_id, "dispatch_node");
    assert_eq!(row.user_id, r.user);
    assert_eq!(row.depth, 1);
    assert_eq!(row.status, ChildRunStatus::Completed);
}

/// A `dispatch` child that CANNOT RUN is recorded as failed — the ledger
/// classifies with check 77's shared classifier over the envelope this
/// function is about to return, so it cannot disagree with what the parent
/// node then does with that same envelope.
///
/// The child here references a module the fetcher does not hold, so the
/// sub-engine's precheck fails and `origin.run_error` builds an `__error`
/// envelope.
///
/// MUTATION: classify with `.as_bool().unwrap_or(false)` — the `__error` here
/// is a STRING, so the row flips to `Completed`.
///
/// **Measured while writing this, and recorded rather than "fixed":** a
/// dispatch child whose terminal MODULE returns `{"__error": "..."}` is
/// recorded `Completed`, because a dispatch envelope is a LABEL-KEYED map of
/// the child's node outputs rather than the collapsed terminal value, so the
/// `__error` sits one level down. That is not a ledger defect — the PARENT
/// node applies `output_reports_error` to the identical envelope and reaches
/// the identical answer, which is exactly the invariant the write site claims.
/// Changing it would change how a `dispatch` node ROUTES, which is not P3's
/// business.
#[tokio::test]
async fn a_dispatch_child_that_cannot_run_is_recorded_as_failed() {
    let module_id = Uuid::new_v4();
    let absent_module = Uuid::new_v4();
    let child_wf = Uuid::new_v4();
    let parent_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "dispatch_node",
            SystemNodeKind::DynamicDispatch {
                dispatch_expression: format!("\"{child_wf}\""),
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");
    let store = KeyedGraphStore::default().with_graph(child_wf, one_module_graph(absent_module));
    let mut r = rig(&parent_graph, store, module_id, json!({}));
    run(&mut r, json!({"ok": true})).await;

    let rows = r.recorder.of_kind(ChildDispatchKind::Dispatch);
    assert_eq!(rows.len(), 1, "the child STARTED, so it gets a row");
    assert_eq!(rows[0].status, ChildRunStatus::Failed);
    assert!(
        rows[0].error_class.is_some(),
        "a failed child carries an error class"
    );
}

// ── C1b: `capability_dispatch` ──────────────────────────────────────────────

/// A `capability_dispatch` node resolves through `resolve_by_capabilities` and
/// records under its OWN kind — the two share
/// `run_dispatched_subworkflow`, so a single `record` call must still produce
/// two distinguishable rows.
///
/// MUTATION: return `ChildDispatchKind::Dispatch` from
/// `DispatchedOrigin::child_dispatch_kind` for both.
#[tokio::test]
async fn a_capability_dispatch_node_records_its_own_kind() {
    let module_id = Uuid::new_v4();
    let cap_wf = Uuid::new_v4();
    let parent_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "cap_node",
            SystemNodeKind::CapabilityDispatch {
                required_capabilities: vec!["p3-cap".to_string()],
                fallback_workflow_id: None,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");
    let store = KeyedGraphStore::default()
        .with_graph(cap_wf, one_module_graph(module_id))
        .with_capabilities(vec!["p3-cap".to_string()], cap_wf);
    let mut r = rig(&parent_graph, store, module_id, json!({"ok": true}));
    run(&mut r, json!({"ok": true})).await;

    let rows = r.recorder.of_kind(ChildDispatchKind::CapabilityDispatch);
    assert_eq!(
        rows.len(),
        1,
        "one capability dispatch, one row: {:?}",
        r.recorder.rows()
    );
    assert_eq!(rows[0].child_workflow_id, cap_wf);
    assert_eq!(rows[0].parent_node_id, "cap_node");
    assert!(
        r.recorder.of_kind(ChildDispatchKind::Dispatch).is_empty(),
        "a capability dispatch must not be filed as a plain dispatch"
    );
}

// ── C2: the loops ───────────────────────────────────────────────────────────

/// An `agent_loop` records ONE ROW PER ITERATION. Folding them would make the
/// ledger disagree with `iterations_run` and with the fuel those iterations
/// burned.
///
/// MUTATION: hoist the `reporter.record(..)` out of the `for iteration` loop,
/// or delete it — three rows become one or none.
#[tokio::test]
async fn an_agent_loop_records_one_row_per_iteration() {
    let module_id = Uuid::new_v4();
    let body_wf = Uuid::new_v4();
    let parent_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "agent_node",
            SystemNodeKind::AgentLoop {
                body_workflow_id: body_wf,
                max_iterations: 3,
                inject_history: false,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");
    let store = KeyedGraphStore::default().with_graph(body_wf, one_module_graph(module_id));
    let mut r = rig(&parent_graph, store, module_id, json!({"finished": false}));
    let execution_id = run(&mut r, json!({"finished": false})).await;

    let rows = r.recorder.of_kind(ChildDispatchKind::AgentLoop);
    assert_eq!(
        rows.len(),
        3,
        "three iterations, three child runs: {:?}",
        r.recorder.rows()
    );
    for row in &rows {
        assert_eq!(row.child_workflow_id, body_wf);
        assert_eq!(row.parent_execution_id, execution_id);
        assert_eq!(row.parent_node_id, "agent_node");
        assert_eq!(row.status, ChildRunStatus::Completed);
    }
}

/// A `react_loop` shares `try_dispatch_agent_loop` at runtime and records
/// `react_loop`: the ledger records what the AUTHOR wrote.
///
/// MUTATION: drop the `ReActLoop` arm of the `loop_kind` match, so every loop
/// files as `agent_loop`.
#[tokio::test]
async fn a_react_loop_records_the_kind_the_author_wrote() {
    let module_id = Uuid::new_v4();
    let body_wf = Uuid::new_v4();
    let parent_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "react_node",
            SystemNodeKind::ReActLoop {
                body_workflow_id: body_wf,
                max_iterations: 2,
                inject_history: false,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");
    let store = KeyedGraphStore::default().with_graph(body_wf, one_module_graph(module_id));
    let mut r = rig(&parent_graph, store, module_id, json!({"finished": false}));
    run(&mut r, json!({"finished": false})).await;

    assert_eq!(
        r.recorder.of_kind(ChildDispatchKind::ReactLoop).len(),
        2,
        "two iterations, two react_loop rows: {:?}",
        r.recorder.rows()
    );
    assert!(
        r.recorder.of_kind(ChildDispatchKind::AgentLoop).is_empty(),
        "a ReActLoop must not be filed as an agent_loop"
    );
}

/// A loop that FINISHES early records only the iterations that ran.
///
/// MUTATION: record once per configured `max_iterations` instead of once per
/// executed iteration.
#[tokio::test]
async fn an_agent_loop_that_finishes_early_records_only_what_ran() {
    let module_id = Uuid::new_v4();
    let body_wf = Uuid::new_v4();
    let parent_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "agent_node",
            SystemNodeKind::AgentLoop {
                body_workflow_id: body_wf,
                max_iterations: 5,
                inject_history: false,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");
    let store = KeyedGraphStore::default().with_graph(body_wf, one_module_graph(module_id));
    let mut r = rig(&parent_graph, store, module_id, json!({"finished": true}));
    run(&mut r, json!({"finished": true})).await;

    assert_eq!(
        r.recorder.of_kind(ChildDispatchKind::AgentLoop).len(),
        1,
        "the body said finished on iteration 1: {:?}",
        r.recorder.rows()
    );
}
