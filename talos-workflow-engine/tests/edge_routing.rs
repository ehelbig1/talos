//! Edge conditions, error edges and skips must mean the same thing after
//! EVERY node kind, and a skip must cascade to a fixed answer.
//!
//! Until 2026-09-25 the rules "a conditional edge is followed only when its
//! condition holds" and "an error edge fires only on failure" were enforced in
//! exactly one place — the success path for WORKER-dispatched modules. Every
//! other node kind committed its output and unblocked its children through a
//! bare counter decrement that consulted neither the condition nor the edge
//! type. So:
//!
//! * a judge with `on_failure: "passthrough"` — documented as existing "so
//!   downstream edges can conditional-route on the verdict" — ran BOTH the
//!   pass branch and the fail branch;
//! * the error-handler child of a sub-workflow (or any system node) ran when
//!   that node SUCCEEDED.
//!
//! And the skip itself was order-dependent: a false condition decremented its
//! grandchildren without enqueuing them, so a merge node ran or silently
//! vanished depending on which of its branches finished last, and anything two
//! levels below a false condition was never resolved at all.
//!
//! These drive the production entry point (`run_with_trigger_input_transport`,
//! chains off) against a dispatcher that records which modules it was asked to
//! run — "was it dispatched" is the property, and a results map alone cannot
//! show a module that ran and was then overwritten.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, DispatchJob, DispatchResult,
    ExpressionEvaluator, NodeDispatcher, SystemNodeKind, WasmModuleArtifact, WorkflowContext,
    WorkflowGraphStore,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

// ── Harness ─────────────────────────────────────────────────────────

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

/// One module per graph node, so "which modules were dispatched" names nodes.
#[derive(Default)]
struct Script {
    /// Per-module output (default `{"ok": true}`).
    outputs: HashMap<Uuid, JsonValue>,
    /// Per-module delay before answering (default none).
    delays: HashMap<Uuid, Duration>,
    /// Modules that fail.
    fail: Vec<Uuid>,
}

struct RecordingDispatcher {
    script: Script,
    dispatched: Mutex<Vec<Uuid>>,
}

impl RecordingDispatcher {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            script,
            dispatched: Mutex::new(Vec::new()),
        })
    }

    fn dispatched(&self) -> Vec<Uuid> {
        self.dispatched.lock().expect("dispatch log").clone()
    }
}

#[async_trait]
impl NodeDispatcher for RecordingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        self.dispatched
            .lock()
            .expect("dispatch log")
            .push(job.module_id);
        if let Some(d) = self.script.delays.get(&job.module_id) {
            tokio::time::sleep(*d).await;
        }
        if self.script.fail.contains(&job.module_id) {
            return Err("module failed".into());
        }
        Ok(DispatchResult {
            output: self
                .script
                .outputs
                .get(&job.module_id)
                .cloned()
                .unwrap_or_else(|| json!({ "ok": true })),
        })
    }

    async fn dispatch_chain(
        &self,
        _request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        Err("chains are disabled on the production entry point".into())
    }
}

/// A deliberately tiny condition language, so each edge's answer is decided by
/// the payload and not by a stub that returns one value for every edge:
/// `true`, `false`, or `<top-level key> == <JSON literal>`. An absent key is
/// an evaluation ERROR, as an unbound variable is in the production Rhai
/// evaluator. `eval_json` parses the expression itself as JSON, which is how
/// an inline judge's verdict is scripted.
struct TinyEvaluator;

impl ExpressionEvaluator for TinyEvaluator {
    fn eval_bool(&self, e: &str, c: &JsonValue) -> bool {
        self.try_eval_bool(e, c).unwrap_or(false)
    }
    fn try_eval_bool(&self, e: &str, c: &JsonValue) -> Result<bool, BoxError> {
        match e.trim() {
            "true" => return Ok(true),
            "false" => return Ok(false),
            _ => {}
        }
        let (key, literal) = e.split_once("==").ok_or("unsupported expression")?;
        let expected: JsonValue = serde_json::from_str(literal.trim())?;
        let actual = c
            .get(key.trim())
            .ok_or_else(|| format!("unbound variable {}", key.trim()))?;
        Ok(*actual == expected)
    }
    fn eval_i64(&self, _e: &str, _c: &JsonValue) -> Option<i64> {
        None
    }
    fn eval_json(&self, e: &str, _c: &JsonValue) -> Result<JsonValue, BoxError> {
        Ok(serde_json::from_str(e)?)
    }
}

/// Serves one graph for every workflow id (the judge / child workflow).
struct OneGraphStore(JsonValue);

#[async_trait]
impl WorkflowGraphStore for OneGraphStore {
    async fn get_graph(
        &self,
        _id: Uuid,
        _user: Uuid,
    ) -> Result<talos_workflow_engine_core::GraphLookup, BoxError> {
        Ok(talos_workflow_engine_core::GraphLookup::Found(
            self.0.clone(),
        ))
    }
    async fn get_graphs(
        &self,
        ids: &[Uuid],
        _user: Uuid,
    ) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        Ok(ids.iter().map(|&id| (id, self.0.clone())).collect())
    }
}

async fn engine_for(graph: &JsonValue, modules: &[Uuid]) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    for &m in modules {
        fetcher = fetcher.with_module(m, stub_artifact(m));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_expression_evaluator(Arc::new(TinyEvaluator));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&serde_json::to_string(graph).unwrap())
        .await
        .expect("graph loads");
    engine
}

async fn run(
    engine: &mut ParallelWorkflowEngine,
    dispatcher: Arc<RecordingDispatcher>,
) -> WorkflowContext {
    engine
        .run_with_trigger_input_transport(dispatcher, None, json!({}), Uuid::new_v4())
        .await
        .expect("run succeeds")
}

fn result_of<'a>(
    engine: &ParallelWorkflowEngine,
    ctx: &'a WorkflowContext,
    label: &str,
) -> Option<&'a JsonValue> {
    let id = engine
        .node_labels()
        .iter()
        .find(|(_, l)| l.as_str() == label)
        .map(|(id, _)| *id)
        .unwrap_or_else(|| panic!("no node labelled {label}"));
    ctx.results.get(&id)
}

fn is_skipped(v: Option<&JsonValue>) -> bool {
    v.and_then(|v| v.get("__skipped"))
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
}

fn error_edge(source: &str, target: &str) -> JsonValue {
    json!({
        "source": source,
        "target": target,
        "sourceHandle": "output",
        "targetHandle": "input",
        "edge_type": "error",
    })
}

// ── Judge passthrough routes exactly ONE conditional branch ─────────

/// `on_failure: "passthrough"` exists so downstream edges can route on
/// `__judge_passed__`. A rejected verdict must run the fail branch and only
/// the fail branch.
#[tokio::test]
async fn judge_passthrough_runs_exactly_one_of_two_conditional_branches() {
    let (draft, judge_mod, pass_mod, fail_mod) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let judge_wf = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("draft", draft, None)
        .add_system_node(
            "judge",
            SystemNodeKind::Judge {
                judge_workflow_id: judge_wf,
                rubric: "is it good".into(),
                pass_threshold: None,
                on_failure: "passthrough".into(),
                timeout_secs: 30,
            },
        )
        .add_module("on_pass", pass_mod, None)
        .add_module("on_fail", fail_mod, None)
        .edge("draft", "judge")
        .edge_condition("judge", "on_pass", "__judge_passed__ == true")
        .edge_condition("judge", "on_fail", "__judge_passed__ == false")
        .build()
        .expect("graph builds");
    // The judge workflow: one module that returns a REJECTING verdict.
    let judge_graph = WorkflowGraphBuilder::new()
        .add_module("verdict", judge_mod, None)
        .build()
        .expect("judge graph builds");

    let mut engine = engine_for(&graph, &[draft, judge_mod, pass_mod, fail_mod]).await;
    engine.set_graph_store(Arc::new(OneGraphStore(judge_graph)));
    let dispatcher = RecordingDispatcher::new(Script {
        outputs: HashMap::from([(
            judge_mod,
            json!({"score": 0.1, "passed": false, "reasoning": "no", "feedback": "redo"}),
        )]),
        ..Script::default()
    });
    let ctx = run(&mut engine, dispatcher.clone()).await;

    let dispatched = dispatcher.dispatched();
    assert!(
        dispatched.contains(&fail_mod),
        "a rejected verdict must run the fail branch"
    );
    assert!(
        !dispatched.contains(&pass_mod),
        "the pass branch's condition is false — it must not be dispatched \
         (dispatched: {dispatched:?})"
    );
    assert!(is_skipped(result_of(&engine, &ctx, "on_pass")));
}

/// Same contract through the synchronous inline judge, which commits through
/// the same system-node path.
#[tokio::test]
async fn inline_judge_passthrough_runs_exactly_one_of_two_conditional_branches() {
    let (draft, pass_mod, fail_mod) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let graph = WorkflowGraphBuilder::new()
        .add_module("draft", draft, None)
        .add_system_node(
            "judge",
            SystemNodeKind::InlineJudge {
                verdict_expr: r#"{"score": 0.9, "passed": true, "reasoning": "fine"}"#.into(),
                pass_threshold: None,
                on_failure: "passthrough".into(),
            },
        )
        .add_module("on_pass", pass_mod, None)
        .add_module("on_fail", fail_mod, None)
        .edge("draft", "judge")
        .edge_condition("judge", "on_pass", "__judge_passed__ == true")
        .edge_condition("judge", "on_fail", "__judge_passed__ == false")
        .build()
        .expect("graph builds");

    let mut engine = engine_for(&graph, &[draft, pass_mod, fail_mod]).await;
    let dispatcher = RecordingDispatcher::new(Script::default());
    let ctx = run(&mut engine, dispatcher.clone()).await;

    let dispatched = dispatcher.dispatched();
    assert!(dispatched.contains(&pass_mod));
    assert!(
        !dispatched.contains(&fail_mod),
        "a passing verdict must not run the fail branch (dispatched: {dispatched:?})"
    );
    assert!(is_skipped(result_of(&engine, &ctx, "on_fail")));
}

// ── Error edges fire only on failure, after every node kind ─────────

#[tokio::test]
async fn subworkflow_success_leaves_its_error_edge_child_skipped() {
    let (child_mod, handler_mod, next_mod) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: Uuid::new_v4(),
                timeout_secs: 30,
            },
        )
        .add_module("handler", handler_mod, None)
        .add_module("next", next_mod, None)
        .add_raw_edge(error_edge("call_child", "handler"))
        .edge("call_child", "next")
        .build()
        .expect("graph builds");
    let child_graph = WorkflowGraphBuilder::new()
        .add_module("work", child_mod, None)
        .build()
        .expect("child graph builds");

    let mut engine = engine_for(&graph, &[child_mod, handler_mod, next_mod]).await;
    engine.set_graph_store(Arc::new(OneGraphStore(child_graph)));
    let dispatcher = RecordingDispatcher::new(Script::default());
    let ctx = run(&mut engine, dispatcher.clone()).await;

    let dispatched = dispatcher.dispatched();
    assert!(
        !dispatched.contains(&handler_mod),
        "an error handler must not run when its sub-workflow SUCCEEDED \
         (dispatched: {dispatched:?})"
    );
    assert!(is_skipped(result_of(&engine, &ctx, "handler")));
    assert!(
        dispatched.contains(&next_mod),
        "the success edge still fires"
    );
}

/// A node skipped by its own `skip_condition` produced no output and did not
/// fail: its error-edge child must not run.
#[tokio::test]
async fn a_skip_condition_skip_does_not_fire_error_edges() {
    let (gated, handler_mod, next_mod) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let graph = WorkflowGraphBuilder::new()
        .add_module("gated", gated, None)
        .add_module("handler", handler_mod, None)
        .add_module("next", next_mod, None)
        .with_skip_condition("gated", "true")
        .add_raw_edge(error_edge("gated", "handler"))
        .edge("gated", "next")
        .build()
        .expect("graph builds");

    let mut engine = engine_for(&graph, &[gated, handler_mod, next_mod]).await;
    let dispatcher = RecordingDispatcher::new(Script::default());
    let ctx = run(&mut engine, dispatcher.clone()).await;

    let dispatched = dispatcher.dispatched();
    assert!(!dispatched.contains(&gated), "the gated node was skipped");
    assert!(
        !dispatched.contains(&handler_mod),
        "a skip is not a failure (dispatched: {dispatched:?})"
    );
    assert!(is_skipped(result_of(&engine, &ctx, "handler")));
    assert!(
        dispatched.contains(&next_mod),
        "an unconditional edge out of a skip_condition skip still fires, as it always has"
    );
}

// ── Skip propagation is a function of the graph, not of timing ──────

/// `a → merge` is live; `x → c (false) → merge` is dead. The merge has a live
/// input, so it runs — whichever branch resolves last. The counter it replaced
/// ran the merge only when the dead branch happened to resolve first.
#[tokio::test]
async fn a_merge_behind_one_live_and_one_dead_branch_runs_in_either_order() {
    for (label, a_delay, x_delay) in [
        (
            "live branch first",
            Duration::ZERO,
            Duration::from_millis(150),
        ),
        (
            "dead branch first",
            Duration::from_millis(150),
            Duration::ZERO,
        ),
    ] {
        let (a, x, c, merge) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let graph = WorkflowGraphBuilder::new()
            .add_module("a", a, None)
            .add_module("x", x, None)
            .add_module("c", c, None)
            .add_module("merge", merge, None)
            .edge("a", "merge")
            .edge_condition("x", "c", "false")
            .edge("c", "merge")
            .build()
            .expect("graph builds");

        let mut engine = engine_for(&graph, &[a, x, c, merge]).await;
        let dispatcher = RecordingDispatcher::new(Script {
            delays: HashMap::from([(a, a_delay), (x, x_delay)]),
            ..Script::default()
        });
        let ctx = run(&mut engine, dispatcher.clone()).await;

        let dispatched = dispatcher.dispatched();
        assert!(
            dispatched.contains(&merge),
            "{label}: the merge has a live input and must run (dispatched: {dispatched:?})"
        );
        assert!(!dispatched.contains(&c), "{label}: c's only edge is false");
        assert!(is_skipped(result_of(&engine, &ctx, "c")), "{label}");
        assert!(!is_skipped(result_of(&engine, &ctx, "merge")), "{label}");
    }
}

/// A skip cascades all the way down, and every node it reaches is recorded as
/// skipped — not left out of the results as though the graph ended early.
#[tokio::test]
async fn a_false_condition_skips_the_whole_subtree_below_it() {
    let (x, c, d, e) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let graph = WorkflowGraphBuilder::new()
        .add_module("x", x, None)
        .add_module("c", c, None)
        .add_module("d", d, None)
        .add_module("e", e, None)
        .edge_condition("x", "c", "false")
        .edge("c", "d")
        .edge("d", "e")
        .build()
        .expect("graph builds");

    let mut engine = engine_for(&graph, &[x, c, d, e]).await;
    let dispatcher = RecordingDispatcher::new(Script::default());
    let ctx = run(&mut engine, dispatcher.clone()).await;

    assert_eq!(dispatcher.dispatched(), vec![x], "only the root runs");
    for label in ["c", "d", "e"] {
        assert!(
            is_skipped(result_of(&engine, &ctx, label)),
            "{label} must be recorded as skipped, got {:?}",
            result_of(&engine, &ctx, label)
        );
    }
}

/// On a failure routed to an error edge, the dead success branch cascades the
/// same way — a merge reachable from the error handler still runs.
#[tokio::test]
async fn a_failure_routed_to_an_error_edge_still_reaches_a_downstream_merge() {
    let (a, ok_path, handler, merge) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let graph = WorkflowGraphBuilder::new()
        .add_module("a", a, None)
        .add_module("ok_path", ok_path, None)
        .add_module("handler", handler, None)
        .add_module("merge", merge, None)
        .edge("a", "ok_path")
        .add_raw_edge(error_edge("a", "handler"))
        .edge("ok_path", "merge")
        .edge("handler", "merge")
        .build()
        .expect("graph builds");

    let mut engine = engine_for(&graph, &[a, ok_path, handler, merge]).await;
    let dispatcher = RecordingDispatcher::new(Script {
        fail: vec![a],
        ..Script::default()
    });
    let ctx = run(&mut engine, dispatcher.clone()).await;

    let dispatched = dispatcher.dispatched();
    assert!(dispatched.contains(&handler));
    assert!(!dispatched.contains(&ok_path));
    assert!(is_skipped(result_of(&engine, &ctx, "ok_path")));
    assert!(
        dispatched.contains(&merge),
        "the merge's error-handler input is live (dispatched: {dispatched:?})"
    );
}

/// A node that skipped ITSELF produced no output, so a conditional edge out
/// of it is inactive WITHOUT being evaluated — even a condition its skip
/// envelope would satisfy. (Evaluating it against the envelope would route on
/// an engine-authored placeholder as though it were the node's output.)
#[tokio::test]
async fn a_conditional_edge_out_of_a_self_skipped_node_is_not_evaluated() {
    let (gated, conditional_child) = (Uuid::new_v4(), Uuid::new_v4());
    let graph = WorkflowGraphBuilder::new()
        .add_module("gated", gated, None)
        .add_module("child", conditional_child, None)
        .with_skip_condition("gated", "true")
        .edge_condition("gated", "child", "__skipped == true")
        .build()
        .expect("graph builds");

    let mut engine = engine_for(&graph, &[gated, conditional_child]).await;
    let dispatcher = RecordingDispatcher::new(Script::default());
    let ctx = run(&mut engine, dispatcher.clone()).await;

    assert!(
        dispatcher.dispatched().is_empty(),
        "neither the gated node nor its conditional child may run: {:?}",
        dispatcher.dispatched()
    );
    assert!(is_skipped(result_of(&engine, &ctx, "child")));
}
