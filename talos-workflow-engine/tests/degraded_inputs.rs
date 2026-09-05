//! A missing input DIMENSION must be visible to the node that composes over
//! it — and to the judge that scores what it composed.
//!
//! Every quality gate in a workflow judges the OUTPUT. When an upstream branch
//! fails and the run is allowed to continue, the output stays perfectly
//! well-formed: it is simply built from less evidence. So an output-only judge
//! structurally cannot see the gap. Observed live on the cross-domain briefing
//! (`pa-chief-of-staff`, 2026-09-03): one of three gather branches died of
//! fuel exhaustion, the fan-in folded its error envelope into `items` as an
//! unlabelled positional element, the composing LLM did exactly what its
//! prompt told it to ("if a source is empty or absent, simply draw fewer
//! priorities from it"), and the deterministic judge scored the result 1.0 —
//! because that verdict only checked the SHAPE of each priority. The words
//! "team", "unavailable" and "degraded" appeared nowhere in a briefing that
//! had lost a third of its evidence.
//!
//! These are CALL-SITE tests on purpose, driving the real reactor. A pure
//! helper's own unit tests cannot see a dispatch branch that never calls it,
//! which is the shape of the defect they exist to prevent.
//!
//! The negative control is not optional here: the whole
//! backward-compatibility claim is "nothing failed ⇒ no key ⇒ byte-identical
//! payload", and only a test that runs the same graph with a healthy parent
//! can establish it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, ExpressionEvaluator, NodeDispatcher, StepStatus, SystemNodeKind,
    WasmModuleArtifact, WorkflowGraphStore,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

const DEGRADED: &str = "__degraded_inputs__";

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

type Seen = Arc<Mutex<Vec<(Uuid, JsonValue)>>>;

/// Records every dispatched input payload by module id. Modules listed in
/// `fail` return `Err`; every other module returns `ok`, except those with a
/// per-module override in `outputs`.
struct RecordingDispatcher {
    fail: Vec<Uuid>,
    ok: JsonValue,
    outputs: HashMap<Uuid, JsonValue>,
    seen: Seen,
}

impl RecordingDispatcher {
    fn new(fail: Vec<Uuid>, ok: JsonValue) -> (Arc<Self>, Seen) {
        Self::with_outputs(fail, ok, HashMap::new())
    }

    fn with_outputs(
        fail: Vec<Uuid>,
        ok: JsonValue,
        outputs: HashMap<Uuid, JsonValue>,
    ) -> (Arc<Self>, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        (
            Arc::new(Self {
                fail,
                ok,
                outputs,
                seen: seen.clone(),
            }),
            seen,
        )
    }

    fn out_for(&self, id: Uuid) -> JsonValue {
        self.outputs.get(&id).cloned().unwrap_or(self.ok.clone())
    }
}

#[async_trait]
impl NodeDispatcher for RecordingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        self.seen
            .lock()
            .expect("seen mutex")
            .push((job.module_id, job.input_payload.clone()));
        if self.fail.contains(&job.module_id) {
            return Err("module blew up".into());
        }
        Ok(DispatchResult {
            output: self.out_for(job.module_id),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        for j in &request.steps {
            self.seen
                .lock()
                .expect("seen mutex")
                .push((j.module_id, j.input_payload.clone()));
        }
        let final_output = request
            .steps
            .last()
            .map(|j| self.out_for(j.module_id))
            .unwrap_or(self.ok.clone());
        let steps: Vec<ChainStepResult> = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: self.out_for(j.module_id),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output,
            overall_status: StepStatus::Success,
        })
    }
}

struct NoGraphStore;

#[async_trait]
impl WorkflowGraphStore for NoGraphStore {
    async fn get_graph(&self, _id: Uuid, _u: Uuid) -> Result<Option<JsonValue>, BoxError> {
        Ok(None)
    }
    async fn get_graphs(
        &self,
        _ids: &[Uuid],
        _u: Uuid,
    ) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        Ok(HashMap::new())
    }
}

/// Records the CONTEXT every verdict expression is evaluated against, and
/// answers with a verdict derived from that context by a closure.
///
/// `minimal_engine` wires `StubExpressionEvaluator`, whose `eval_json` returns
/// a constant and never so much as looks at the expression — so a judge test
/// built on it scores whatever `JudgeVerdict::from_collapsed` makes of that
/// constant, on a healthy run and a degraded one alike. Two of the tests below
/// were green under exactly that mistake until the healthy-run control caught
/// them. This evaluator restores the only claim the ENGINE actually owns: what
/// it hands the evaluator. Whether Rhai then binds `inputs_degraded` correctly
/// is `talos-engine`'s to prove, in `rhai_helpers`' own unit tests — this crate
/// cannot dev-depend on that one without a dependency cycle.
struct CapturingEvaluator {
    seen: Arc<Mutex<Vec<JsonValue>>>,
}

impl CapturingEvaluator {
    fn new() -> (Arc<Self>, Arc<Mutex<Vec<JsonValue>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        (Arc::new(Self { seen: seen.clone() }), seen)
    }
}

impl ExpressionEvaluator for CapturingEvaluator {
    fn eval_bool(&self, _e: &str, _c: &JsonValue) -> bool {
        true
    }
    fn try_eval_bool(&self, _e: &str, _c: &JsonValue) -> Result<bool, BoxError> {
        Ok(true)
    }
    fn eval_i64(&self, _e: &str, _c: &JsonValue) -> Option<i64> {
        None
    }
    fn eval_json(&self, _expression: &str, context: &JsonValue) -> Result<JsonValue, BoxError> {
        self.seen.lock().expect("eval mutex").push(context.clone());
        // Stands in for the author's rule `passed: !inputs_degraded`. The
        // engine's job is to put the fact in the context; this closes the loop
        // so the verdict actually DISCRIMINATES between the two runs.
        let degraded = context
            .get(DEGRADED)
            .and_then(|r| r.get("any_degraded"))
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        Ok(json!({
            "score": if degraded { 0.0 } else { 1.0 },
            "passed": !degraded,
            "reasoning": "a brief built on partial evidence must say so",
        }))
    }
}

fn engine_for(parent: &JsonValue, modules: &[Uuid]) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    for m in modules {
        fetcher = fetcher.with_module(*m, stub_artifact(*m));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_graph_store(Arc::new(NoGraphStore));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    futures::executor::block_on(
        engine.load_graph_from_json(&serde_json::to_string(parent).expect("graph serializes")),
    )
    .expect("parent graph loads");
    engine
}

fn input_to(seen: &Seen, module: Uuid) -> JsonValue {
    seen.lock()
        .expect("seen mutex")
        .iter()
        .find(|(m, _)| *m == module)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("module {module} was never dispatched"))
}

/// The flagship's shape: three gather branches fan into a `collect`, which
/// feeds a composer, which feeds a judge.
fn briefing_graph(
    personal: Uuid,
    team: Uuid,
    ops: Uuid,
    compose: Uuid,
    verdict_expr: &str,
) -> JsonValue {
    WorkflowGraphBuilder::new()
        .add_module("pa_gather", personal, None)
        .add_module("team_gather", team, None)
        .add_module("ops_gather", ops, None)
        .add_system_node("collect", SystemNodeKind::Collect)
        .add_module("synthesize", compose, None)
        .add_system_node(
            "judge",
            SystemNodeKind::InlineJudge {
                verdict_expr: verdict_expr.to_string(),
                pass_threshold: Some(0.6),
                on_failure: "passthrough".to_string(),
            },
        )
        // `team_gather` opts into degradation. Without this the run FAILS
        // outright (#734) — which is the correct default and precisely why a
        // visible-degradation path has to exist: the alternative to a silent
        // gap should not be throwing away a briefing that is 90% useful.
        .with_continue_on_error("team_gather")
        .edge("pa_gather", "collect")
        .edge("team_gather", "collect")
        .edge("ops_gather", "collect")
        .edge("collect", "synthesize")
        .edge("synthesize", "judge")
        .build()
        .expect("graph builds")
}

/// A verdict that only checks the SHAPE of the composed output — the real
/// flagship judge, reduced to its essence.
const SHAPE_ONLY_VERDICT: &str = r#"#{ score: if type_of(priorities) == "array" && priorities.len() > 0 { 1.0 } else { 0.0 }, passed: type_of(priorities) == "array" && priorities.len() > 0, reasoning: "shape only" }"#;

// ── The defect, and its control ─────────────────────────────────────

#[tokio::test]
async fn a_failed_branch_is_named_on_the_composer_input() {
    let (personal, team, ops, compose) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let graph = briefing_graph(personal, team, ops, compose, SHAPE_ONLY_VERDICT);
    let (dispatcher, seen) = RecordingDispatcher::new(vec![team], json!({ "rows": [1, 2] }));
    let engine = engine_for(&graph, &[personal, team, ops, compose]);

    engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("continue_on_error keeps the run alive");

    let report = input_to(&seen, compose)
        .get(DEGRADED)
        .cloned()
        .expect("the composer's input names the branch it lost");

    assert_eq!(report["any_degraded"], json!(true));
    assert_eq!(report["count"], json!(1));
    assert_eq!(
        report["entries"][0]["node"],
        json!("team_gather"),
        "the report must NAME the branch: `collect` folds it into a positional \
         `items` array whose order is `neighbors_directed`'s, not the author's, \
         so position is not a usable proxy for identity — report was {report}"
    );
    assert!(
        report["entries"][0]["reason"]
            .as_str()
            .expect("reason is a string")
            .contains("module blew up"),
        "the reason must survive to the composer, got {report}"
    );
}

#[tokio::test]
async fn a_healthy_run_carries_no_key_at_all() {
    // The negative control. The backward-compatibility claim is not "the key
    // is empty" but "there is no key", so absence is what must be asserted:
    // an all-clear envelope would change every existing payload.
    let (personal, team, ops, compose) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let graph = briefing_graph(personal, team, ops, compose, SHAPE_ONLY_VERDICT);
    let (dispatcher, seen) = RecordingDispatcher::new(vec![], json!({ "rows": [1, 2] }));
    let engine = engine_for(&graph, &[personal, team, ops, compose]);

    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("healthy run completes");

    let composer_input = input_to(&seen, compose);
    assert!(
        composer_input.get(DEGRADED).is_none(),
        "a run with no failed ancestor must be byte-identical to the \
         pre-feature payload, got {composer_input}"
    );
    for (id, out) in &ctx.results {
        assert!(
            out.get(DEGRADED).is_none(),
            "node {id} output carries {DEGRADED} on a healthy run: {out}"
        );
    }
}

// ── Transitivity: the judge is three hops from the failure ──────────

#[tokio::test]
async fn the_judge_sees_a_failure_three_hops_upstream() {
    // `judge → synthesize → collect → team_gather`. Only `collect` has the
    // failed node as a DIRECT parent, and `collect` is the one node in the
    // chain that renders nothing and judges nothing. A direct-parents-only
    // report would put the signal exactly where nobody can act on it.
    let (personal, team, ops, compose) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let graph = briefing_graph(personal, team, ops, compose, SHAPE_ONLY_VERDICT);
    let (dispatcher, _seen) =
        RecordingDispatcher::new(vec![team], json!({ "priorities": [{ "title": "x" }] }));
    let (evaluator, contexts) = CapturingEvaluator::new();
    let mut engine = engine_for(&graph, &[personal, team, ops, compose]);
    engine.set_expression_evaluator(evaluator);

    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("passthrough on_failure keeps the run alive");

    let judged = contexts.lock().expect("ctx mutex").clone();
    assert_eq!(judged.len(), 1, "exactly one verdict was evaluated");
    assert_eq!(
        judged[0][DEGRADED]["entries"][0]["node"],
        json!("team_gather"),
        "the verdict expression's context must name the lost branch — the \
         judge is three hops from the failure and its own parent did not fail, \
         got {}",
        judged[0]
    );

    let verdict = ctx
        .results
        .values()
        .find(|v| v.get("__judge_score__").is_some())
        .cloned()
        .expect("the judge produced a verdict");
    assert_eq!(
        verdict["__judge_score__"],
        json!(0.0),
        "an author's rule CAN now act on it; pre-change this graph scored a \
         perfect 1.0 on a briefing missing a third of its evidence — {verdict}"
    );
    assert_eq!(verdict["__judge_passed__"], json!(false));
    assert_eq!(
        verdict["__judge_rejected__"],
        json!(true),
        "on_failure=passthrough marks the verdict rejected without failing the run"
    );
}

#[tokio::test]
async fn the_judge_still_passes_when_nothing_degraded() {
    // Positive control for the test above, and it earned its place: without
    // it, both judge tests were green while the stub evaluator ignored the
    // expression entirely and returned score 0 on EVERY run. A detector that
    // fires on the healthy case too is not a detector.
    let (personal, team, ops, compose) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let graph = briefing_graph(personal, team, ops, compose, SHAPE_ONLY_VERDICT);
    let (dispatcher, _seen) =
        RecordingDispatcher::new(vec![], json!({ "priorities": [{ "title": "x" }] }));
    let (evaluator, contexts) = CapturingEvaluator::new();
    let mut engine = engine_for(&graph, &[personal, team, ops, compose]);
    engine.set_expression_evaluator(evaluator);

    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("healthy run completes");

    let judged = contexts.lock().expect("ctx mutex").clone();
    assert!(
        judged[0].get(DEGRADED).is_none(),
        "a healthy run must hand the verdict a context with NO key at all, \
         got {}",
        judged[0]
    );
    let verdict = ctx
        .results
        .values()
        .find(|v| v.get("__judge_score__").is_some())
        .cloned()
        .expect("the judge produced a verdict");
    assert_eq!(verdict["__judge_score__"], json!(1.0));
    assert_eq!(verdict["__judge_passed__"], json!(true));
}

// ── The fan-in's own half ───────────────────────────────────────────

#[tokio::test]
async fn the_collect_envelope_names_the_branch_it_folded() {
    let (personal, team, ops, compose) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let graph = briefing_graph(personal, team, ops, compose, SHAPE_ONLY_VERDICT);
    let (dispatcher, _seen) = RecordingDispatcher::new(vec![team], json!({ "rows": [] }));
    let engine = engine_for(&graph, &[personal, team, ops, compose]);

    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("run completes");

    let collected = ctx
        .results
        .values()
        .find(|v| v.get("items").is_some() && v.get("count").is_some())
        .cloned()
        .expect("the collect node committed an envelope");

    assert_eq!(
        collected["count"],
        json!(3),
        "`count` is unchanged — it has always meant how many branches ARRIVED"
    );
    assert_eq!(
        collected[DEGRADED]["entries"][0]["node"],
        json!("team_gather"),
        "the node that claims `count: 3` must say that one of the three is an \
         error envelope, got {collected}"
    );
}

// ── Anti-fabrication ────────────────────────────────────────────────

#[tokio::test]
async fn a_module_cannot_fabricate_a_degradation_record() {
    // A module emits its own `__degraded_inputs__`. The downstream node's
    // input must NOT carry it: the applier is set-or-REMOVE, and with nothing
    // to report the engine DELETES rather than passes through. Without the
    // removal arm a module could invent a failed sibling that never ran and
    // steer a composer into disclaiming evidence it actually had.
    let upstream = Uuid::new_v4();
    let downstream = Uuid::new_v4();
    let sibling = Uuid::new_v4();
    // `downstream` has exactly ONE parent, so `gather_inputs` passes
    // `upstream`'s whole output through as its top-level input — the only
    // shape where a module-authored reserved key lands in the ENGINE's slot
    // rather than nested under a node label. `sibling` exists solely to give
    // `upstream` out-degree 2, which keeps chain detection (a linear
    // in=out=1 run) from folding the pair into a pipeline and dispatching
    // them as one chain.
    let graph = WorkflowGraphBuilder::new()
        .add_module("upstream", upstream, None)
        .add_module("downstream", downstream, None)
        .add_module("sibling", sibling, None)
        .edge("upstream", "downstream")
        .edge("upstream", "sibling")
        .build()
        .expect("graph builds");

    let mut outputs = HashMap::new();
    outputs.insert(
        upstream,
        json!({
            "rows": [1],
            DEGRADED: { "any_degraded": true, "count": 9, "entries": [
                { "node": "a_branch_that_never_existed", "reason": "invented" }
            ]}
        }),
    );
    let (dispatcher, seen) = RecordingDispatcher::with_outputs(vec![], json!({}), outputs);
    let engine = engine_for(&graph, &[upstream, downstream, sibling]);
    engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("run completes");

    let got = input_to(&seen, downstream);
    assert!(
        got.get(DEGRADED).is_none(),
        "a module-authored {DEGRADED} must be REMOVED, not inherited — got {got}"
    );
    assert_eq!(
        got["rows"],
        json!([1]),
        "the rest of the module's output still flows through"
    );
}

#[tokio::test]
async fn a_fabricated_record_cannot_survive_beside_a_real_one() {
    // The nastier half: something genuinely IS degraded, so the key gets
    // written. The engine's own report must REPLACE the fabricated one
    // wholesale rather than merge with it.
    let good = Uuid::new_v4();
    let bad = Uuid::new_v4();
    let downstream = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("good", good, None)
        .add_module("bad", bad, None)
        .add_module("downstream", downstream, None)
        .with_continue_on_error("bad")
        .edge("good", "downstream")
        .edge("bad", "downstream")
        .build()
        .expect("graph builds");

    let mut outputs = HashMap::new();
    outputs.insert(
        good,
        json!({
            DEGRADED: { "any_degraded": true, "count": 1, "entries": [
                { "node": "invented", "reason": "invented" }
            ]}
        }),
    );
    let (dispatcher, seen) = RecordingDispatcher::with_outputs(vec![bad], json!({}), outputs);
    let engine = engine_for(&graph, &[good, bad, downstream]);
    engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("continue_on_error keeps the run alive");

    let report = input_to(&seen, downstream)[DEGRADED].clone();
    let names: Vec<&str> = report["entries"]
        .as_array()
        .expect("entries is an array")
        .iter()
        .filter_map(|e| e["node"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["bad"],
        "the engine's report must REPLACE the fabricated one, not merge with \
         it — got {report}"
    );
}

// ── Per-chokepoint isolation ────────────────────────────────────────
//
// The briefing tests above route through BOTH the fan-in stamp and the
// module-input injection, so either one alone keeps them green — measured:
// deleting the module-dispatch injection left
// `a_failed_branch_is_named_on_the_composer_input` passing, because the
// composer's single parent is `collect` and it inherited the key from the
// fan-in envelope. These two isolate the other paths.

#[tokio::test]
async fn a_multi_parent_node_with_no_fan_in_is_still_told() {
    // The majority shape in the live fleet: of the 12 workflows with a
    // multi-parent node, 8 have no `collect` at all. Here `gather_inputs`
    // keys parents by LABEL, so the failed parent's envelope is nested under
    // its own name and the TOP-LEVEL report can only have come from the
    // module-dispatch chokepoint.
    let good = Uuid::new_v4();
    let bad = Uuid::new_v4();
    let composer = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("good", good, None)
        .add_module("bad", bad, None)
        .add_module("composer", composer, None)
        .with_continue_on_error("bad")
        .edge("good", "composer")
        .edge("bad", "composer")
        .build()
        .expect("graph builds");

    let (dispatcher, seen) = RecordingDispatcher::new(vec![bad], json!({ "rows": [1] }));
    let engine = engine_for(&graph, &[good, bad, composer]);
    engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("continue_on_error keeps the run alive");

    let got = input_to(&seen, composer);
    assert_eq!(
        got[DEGRADED]["entries"][0]["node"],
        json!("bad"),
        "a fan-in node is not required for the signal — got {got}"
    );
}

#[tokio::test]
async fn a_pipeline_chain_is_told_at_its_head() {
    // Chains dispatch as ONE `dispatch_chain` and assemble their envelope in a
    // different function from single-node dispatch — the classic place for a
    // signal to be wired at one site and missed at the other.
    //
    // The topology is dictated by `detect_linear_chains`: a chain STARTS at an
    // out-degree-1 node whose parent branches (out-degree != 1). Hence `bad`
    // fanning out to `head` and `spare` — the first version of this test used a
    // fan-IN into `head`, which produces no chain at all, and the assertion
    // then passed on the single-node path while the pipeline site was
    // unreachable. Measured by mutation: deleting the pipeline injection left
    // that version green.
    let bad = Uuid::new_v4();
    let spare = Uuid::new_v4();
    let head = Uuid::new_v4();
    let tail = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("bad", bad, None)
        .add_module("spare", spare, None)
        .add_module("head", head, None)
        .add_module("tail", tail, None)
        .with_continue_on_error("bad")
        .edge("bad", "head")
        .edge("bad", "spare")
        .edge("head", "tail")
        .build()
        .expect("graph builds");

    let (dispatcher, seen) = RecordingDispatcher::new(vec![bad], json!({ "rows": [1] }));
    let engine = engine_for(&graph, &[bad, spare, head, tail]);
    engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("continue_on_error keeps the run alive");

    // Located by the `pipeline_input` wrapper rather than by module id: the
    // chain path resolves its steps through `resolve_module_id`, which for a
    // graph node with no `node_meta` module hands back the node's own
    // SHA-derived uuid — so the ids recorded here are not the artifact ids the
    // single-node path records.
    let got = seen
        .lock()
        .expect("seen mutex")
        .iter()
        .map(|(_, v)| v.clone())
        .find(|v| v.get("pipeline_input").is_some())
        .expect("a pipeline chain was dispatched; if not, the topology no longer forms a chain");
    assert_eq!(
        got[DEGRADED]["entries"][0]["node"],
        json!("bad"),
        "the chain head's assembled envelope must name the lost branch — got {got}"
    );
}
