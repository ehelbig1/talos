//! An `expression_dispatch` node starts only a workflow its author declared
//! (security review 2026-10-14, G-7).
//!
//! The node's expression usually reads its input (`inputs.route`), so
//! whoever wrote that input chose which of the owner's workflows ran — any of
//! them, by UUID or by name. When the node declares `targets`, the workflow
//! the expression resolves to must be one of them, or the node fails and the
//! refusal is counted; undeclared is the legacy reading.
//!
//! The graph store here serves two child workflows the running user OWNS, so
//! every refusal below is the declaration's, not tenancy's.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;

use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, GraphLookup, NodeDispatcher, StepStatus, SystemNodeKind, WasmModuleArtifact,
    WorkflowGraphStore,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};

/// Counts the module jobs it is handed, per module.
#[derive(Default)]
struct CountingDispatcher {
    jobs: std::sync::Mutex<HashMap<Uuid, usize>>,
    total: AtomicUsize,
}

impl CountingDispatcher {
    fn jobs_for(&self, module: Uuid) -> usize {
        self.jobs.lock().unwrap().get(&module).copied().unwrap_or(0)
    }
}

#[async_trait]
impl NodeDispatcher for CountingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        self.total.fetch_add(1, Ordering::SeqCst);
        *self.jobs.lock().unwrap().entry(job.module_id).or_default() += 1;
        Ok(DispatchResult {
            output: json!({ "ran": job.module_id.to_string() }),
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
                output: json!({}),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: json!({}),
            overall_status: StepStatus::Success,
        })
    }
}

/// Two children of the running user's, one of them also findable by name.
struct Store {
    graphs: HashMap<Uuid, JsonValue>,
    by_name: HashMap<String, Uuid>,
}

#[async_trait]
impl WorkflowGraphStore for Store {
    async fn get_graph(&self, id: Uuid, _user: Uuid) -> Result<GraphLookup, BoxError> {
        Ok(self
            .graphs
            .get(&id)
            .cloned()
            .map_or(GraphLookup::Absent, GraphLookup::Found))
    }
    async fn get_graphs(
        &self,
        ids: &[Uuid],
        _user: Uuid,
    ) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        Ok(ids
            .iter()
            .filter_map(|id| self.graphs.get(id).map(|g| (*id, g.clone())))
            .collect())
    }
    async fn resolve_by_name(&self, name: &str, _user: Uuid) -> Result<Option<Uuid>, BoxError> {
        Ok(self.by_name.get(name).copied())
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

fn one_module_graph(module_id: Uuid) -> JsonValue {
    WorkflowGraphBuilder::new()
        .add_module(module_id.to_string(), module_id, None)
        .build()
        .expect("child graph builds")
}

/// The two children: `declared` (the author listed it) and `other` (also the
/// owner's, and findable by the name `send-html-email`), each one module.
struct World {
    declared: Uuid,
    declared_module: Uuid,
    other: Uuid,
    other_module: Uuid,
}

fn world() -> World {
    World {
        declared: Uuid::new_v4(),
        declared_module: Uuid::new_v4(),
        other: Uuid::new_v4(),
        other_module: Uuid::new_v4(),
    }
}

/// Run `dispatch` (the only node) with `expression` and `targets`; returns
/// the run's outcome and the dispatcher.
async fn run(
    w: &World,
    expression: String,
    targets: Option<Vec<Uuid>>,
) -> (Result<(), String>, Arc<CountingDispatcher>) {
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "dispatch",
            SystemNodeKind::DynamicDispatch {
                dispatch_expression: expression,
                timeout_secs: 30,
                targets,
            },
        )
        .build()
        .expect("parent graph builds");
    let store = Store {
        graphs: HashMap::from([
            (w.declared, one_module_graph(w.declared_module)),
            (w.other, one_module_graph(w.other_module)),
        ]),
        by_name: HashMap::from([("send-html-email".to_string(), w.other)]),
    };
    let mut engine: ParallelWorkflowEngine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_workflow_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(w.declared_module, stub_artifact(w.declared_module))
            .with_module(w.other_module, stub_artifact(w.other_module)),
    ));
    engine.set_graph_store(Arc::new(store));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&serde_json::to_string(&parent).unwrap())
        .await
        .expect("parent graph loads");
    let dispatcher = Arc::new(CountingDispatcher::default());
    let outcome = engine
        .run_with_trigger_input_transport(dispatcher.clone(), None, json!({}), Uuid::new_v4())
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    (outcome, dispatcher)
}

fn refusals_so_far() -> f64 {
    if talos_metrics::global().is_none() {
        if let Ok(m) = talos_metrics::TalosMetrics::new() {
            talos_metrics::set_global(m);
        }
    }
    talos_metrics::global()
        .expect("metrics installed")
        .expression_dispatch_target_refusals_total
        .get()
}

#[tokio::test]
async fn an_owned_workflow_the_author_did_not_declare_is_refused_and_counted() {
    let w = world();
    let before = refusals_so_far();
    let (outcome, dispatcher) = run(&w, format!("\"{}\"", w.other), Some(vec![w.declared])).await;
    let err = outcome.expect_err("an undeclared target must fail the node");
    assert!(err.contains("declared targets"), "{err}");
    assert_eq!(
        dispatcher.total.load(Ordering::SeqCst),
        0,
        "the undeclared child ran"
    );
    assert!(
        refusals_so_far() >= before + 1.0,
        "the refusal was not counted"
    );
}

#[tokio::test]
async fn a_name_that_resolves_to_an_undeclared_workflow_is_refused_too() {
    let w = world();
    let (outcome, dispatcher) = run(
        &w,
        "\"send-html-email\"".to_string(),
        Some(vec![w.declared]),
    )
    .await;
    let err = outcome.expect_err("a name is checked by what it resolves to");
    assert!(err.contains("declared targets"), "{err}");
    assert_eq!(dispatcher.jobs_for(w.other_module), 0);
}

#[tokio::test]
async fn a_declared_target_is_dispatched() {
    let w = world();
    let (outcome, dispatcher) =
        run(&w, format!("\"{}\"", w.declared), Some(vec![w.declared])).await;
    outcome.expect("a declared target runs");
    assert_eq!(dispatcher.jobs_for(w.declared_module), 1);
}

/// The legacy reading, unchanged: no declaration, any workflow the
/// expression names that resolves for the running user.
#[tokio::test]
async fn an_undeclared_node_keeps_the_legacy_reading() {
    let w = world();
    let (outcome, dispatcher) = run(&w, format!("\"{}\"", w.other), None).await;
    outcome.expect("legacy dispatch runs");
    assert_eq!(dispatcher.jobs_for(w.other_module), 1);
}

/// A declaration the engine cannot read admits nothing.
#[tokio::test]
async fn an_empty_declaration_admits_nothing() {
    let w = world();
    let (outcome, dispatcher) = run(&w, format!("\"{}\"", w.declared), Some(vec![])).await;
    assert!(outcome.is_err(), "an empty declared set started a workflow");
    assert_eq!(dispatcher.total.load(Ordering::SeqCst), 0);
}
