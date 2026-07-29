//! Workflow-level timeout enforcement.
//!
//! `ParallelWorkflowEngine::execution_timeout_secs` is documented as
//! the "maximum execution time for the entire workflow." Before the
//! scheduler unification the fresh-run path (`run_with_transport`)
//! silently ignored the field — a runaway workflow could hold
//! resources indefinitely even with the timeout set. These tests
//! lock in that the field is now enforced on both entry points:
//!
//! * [`run_with_transport`](talos_workflow_engine::ParallelWorkflowEngine::run_with_transport)
//!   — the fresh path.
//! * [`run_with_seed_with_transport`](talos_workflow_engine::ParallelWorkflowEngine::run_with_seed_with_transport)
//!   — the seeded-resume path (always enforced historically).
//! * `execution_timeout_secs = 0` opts out: the scheduler runs
//!   without a wall-clock cap so only per-node timeouts apply. This
//!   lane is tested separately so the "explicit opt-out" contract
//!   stays stable.
//!
//! The tests use a dispatcher that parks for 10 seconds before
//! returning. With `execution_timeout_secs = 1` the reactor is
//! wrapped in a 1-second `tokio::time::timeout` that trips first;
//! with `execution_timeout_secs = 0` the dispatcher's output is
//! observed, confirming the timeout is disabled rather than
//! applied-to-zero.

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
use uuid::Uuid;

/// Dispatcher that parks `dispatch` for `delay` before returning a
/// canned success. Lets a workflow-level timeout trip first, without
/// the dispatcher ever observing the cancellation.
struct SleepingDispatcher {
    delay: Duration,
}

#[async_trait]
impl NodeDispatcher for SleepingDispatcher {
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

/// A three-node fan-out graph ("root" → [a, b]) so the scheduler does
/// real dispatch work on the *single-node* path. A two-node `a → b`
/// linear graph would trigger the pipeline-chain optimisation
/// (`detect_linear_chains`), whose wire format sets
/// `DispatchJob.module_id = node_id` rather than the resolved template
/// UUID — `ScriptedDispatcher` keys responses by `module_id` and
/// wouldn't find them. Fan-out keeps every node on the per-node
/// dispatch path.
fn build_slow_graph() -> (serde_json::Value, Uuid, Uuid, Uuid) {
    let root_mod = Uuid::new_v4();
    let a_mod = Uuid::new_v4();
    let b_mod = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("root", root_mod, None)
        .add_module("a", a_mod, None)
        .add_module("b", b_mod, None)
        .edge("root", "a")
        .edge("root", "b")
        .build()
        .expect("builder inputs well-formed");
    (graph, root_mod, a_mod, b_mod)
}

fn engine_with_timeout(
    secs: u64,
    root_mod: Uuid,
    a_mod: Uuid,
    b_mod: Uuid,
) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    let fetcher = Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(root_mod, stub_artifact(root_mod))
            .with_module(a_mod, stub_artifact(a_mod))
            .with_module(b_mod, stub_artifact(b_mod)),
    );
    engine.set_module_fetcher(fetcher);
    engine.set_user_id(Uuid::new_v4());
    engine.set_execution_timeout_secs(secs);
    engine
}

#[tokio::test]
async fn run_with_transport_enforces_workflow_timeout() {
    // Regression test for the scheduler-unification commit: the fresh
    // path previously ignored execution_timeout_secs entirely. This
    // test fails on a pre-unification engine because the workflow
    // would wait for the dispatcher's 10-second sleep to finish
    // (and then another 10s for the downstream node).
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(1, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(SleepingDispatcher {
        delay: Duration::from_secs(10),
    });
    let started = std::time::Instant::now();
    let err = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("workflow must time out");
    let elapsed = started.elapsed();

    // The timeout failure mode is a typed `WorkflowEngineError::Timeout`
    // variant — pattern-match it so we catch a regression to the
    // catch-all `Execution(String)` form rather than only relying on
    // a substring match.
    assert!(
        matches!(err, WorkflowEngineError::Timeout { secs: 1, .. }),
        "expected Timeout {{ secs: 1 }}, got: {err:?}"
    );
    // Elapsed should be close to the 1-second cap — give generous
    // slack for CI scheduling but fail if it took as long as the
    // dispatcher's natural sleep.
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout took {elapsed:?}, expected ~1s"
    );
}

#[tokio::test]
async fn run_with_seed_with_transport_enforces_workflow_timeout() {
    // Complement to the fresh-path test: the seeded path has always
    // enforced the timeout; this test locks that behaviour in post-
    // unification.
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(1, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(SleepingDispatcher {
        delay: Duration::from_secs(10),
    });
    let started = std::time::Instant::now();
    // Seed with an empty map — we want the dispatcher to actually run
    // and sleep so the scheduler's timer is what bounds the wait.
    let err = engine
        .run_with_seed_with_transport(
            dispatcher,
            None,
            std::collections::HashMap::new(),
            Uuid::new_v4(),
        )
        .await
        .expect_err("workflow must time out");
    let elapsed = started.elapsed();
    assert!(
        matches!(err, WorkflowEngineError::Timeout { secs: 1, .. }),
        "expected Timeout {{ secs: 1 }}, got: {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout took {elapsed:?}, expected ~1s"
    );
}

#[tokio::test]
async fn typed_execution_timeout_round_trips() {
    // The Option<Duration> setter is the preferred form for new code.
    // Verify both sides of the API agree on the disabled / enabled
    // distinction so callers can mix them without surprises.
    let mut engine = ParallelWorkflowEngine::new();

    engine.set_execution_timeout(None);
    assert_eq!(engine.execution_timeout(), None);
    assert_eq!(engine.execution_timeout_secs(), 0);

    engine.set_execution_timeout(Some(Duration::from_secs(120)));
    assert_eq!(engine.execution_timeout(), Some(Duration::from_secs(120)));
    assert_eq!(engine.execution_timeout_secs(), 120);

    // Bridging through the legacy setter still produces a coherent
    // typed read — `0` is the documented disable sentinel.
    engine.set_execution_timeout_secs(0);
    assert_eq!(engine.execution_timeout(), None);

    engine.set_execution_timeout_secs(45);
    assert_eq!(engine.execution_timeout(), Some(Duration::from_secs(45)));
}

#[tokio::test]
async fn execution_timeout_secs_zero_disables_the_cap() {
    // Opt-out lane: setting the field to 0 should let the workflow
    // run to completion (bounded by per-node timeouts only). We use
    // a ScriptedDispatcher returning immediately so the test finishes
    // in milliseconds even with no workflow-level cap.
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(0, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(root_mod, json!({"output": "root"}))
            .with_response(a_mod, json!({"output": "a"}))
            .with_response(b_mod, json!({"output": "b"})),
    );
    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("no timeout when execution_timeout_secs = 0");
    assert_eq!(ctx.results.len(), 3, "all three nodes should complete");
}

// ============================================================================
// Timeout attribution — the error must name the node holding the clock.
//
// Motivation: `pa-chief-of-staff` timed out twice in production with
// "workflow execution timed out after 180 seconds" and nothing else. The
// culprit (`synthesize`, an LLM node whose cold-start pushed it past the
// cap) had to be reconstructed from node-timing archaeology across prior
// runs. These tests lock in that the attribution is present, correct, and
// carries node identity + timings ONLY.
// ============================================================================

/// Canary planted in node `b`'s CONFIG. It must never appear in a
/// timeout message — the string flows into
/// `workflow_executions.error_message`, the operator digest preview, and
/// the failure webhook. Node config is exactly the kind of content
/// (API hosts, prompts, header templates) that must not leak there.
const CONFIG_CANARY: &str = "CONFIG_CANARY_do_not_leak_9f3a";

/// Canary returned as node `a`'s OUTPUT — the other half of the DLP
/// contract. `a` completes before the timeout fires, so its output is
/// live in the engine's results map at the moment the message is built.
const OUTPUT_CANARY: &str = "OUTPUT_CANARY_do_not_leak_51bd";

/// Dispatcher that answers instantly for every module except one, which
/// it parks on. Lets a test pin exactly which node is in flight when the
/// wall-clock cap trips.
struct SelectiveSleepingDispatcher {
    slow_module: Uuid,
    delay: Duration,
    slow_output_for: Uuid,
}

#[async_trait]
impl NodeDispatcher for SelectiveSleepingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        if job.module_id == self.slow_module {
            tokio::time::sleep(self.delay).await;
        }
        let output = if job.module_id == self.slow_output_for {
            json!({"output": OUTPUT_CANARY})
        } else {
            json!({"output": "fast"})
        };
        Ok(DispatchResult { output })
    }

    async fn dispatch_chain(
        &self,
        _request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        unreachable!("fan-out graph keeps every node on the single-node path")
    }
}

/// Same fan-out topology as `build_slow_graph`, but node `b` carries a
/// config canary so the DLP assertion has something real to look for.
fn build_attribution_graph() -> (serde_json::Value, Uuid, Uuid, Uuid) {
    let root_mod = Uuid::new_v4();
    let a_mod = Uuid::new_v4();
    let b_mod = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("root", root_mod, None)
        .add_module("a", a_mod, None)
        .add_module(
            "b",
            b_mod,
            Some(json!({ "API_ENDPOINT": CONFIG_CANARY, "MODEL": "qwen3.6:latest" })),
        )
        .edge("root", "a")
        .edge("root", "b")
        .build()
        .expect("builder inputs well-formed");
    (graph, root_mod, a_mod, b_mod)
}

#[tokio::test]
async fn timeout_message_names_the_in_flight_node_and_completed_count() {
    let (graph_json, root_mod, a_mod, b_mod) = build_attribution_graph();
    let mut engine = engine_with_timeout(2, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    // `root` and `a` return instantly; `b` parks well past the 2s cap.
    let dispatcher = Arc::new(SelectiveSleepingDispatcher {
        slow_module: b_mod,
        delay: Duration::from_secs(30),
        slow_output_for: a_mod,
    });
    let err = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("workflow must time out");
    let msg = err.to_string();

    // The base contract is unchanged...
    assert!(
        msg.starts_with("workflow execution timed out after 2 seconds"),
        "base message changed: {msg}"
    );
    // ...and the attribution names the node that was actually holding
    // the clock. This is the assertion that fails if a refactor drops
    // the progress snapshot on the floor.
    assert!(
        msg.contains("in flight: b "),
        "expected the stalled node named, got: {msg}"
    );
    // `root` and `a` both completed before the cap tripped.
    assert!(
        msg.contains("2 nodes completed"),
        "expected completed count of 2, got: {msg}"
    );
    // Elapsed is rendered for the in-flight node. At a 2s cap it has
    // been running ~2s (root's round trip is sub-millisecond), so the
    // seconds form must be present rather than a bare label.
    assert!(
        msg.contains("in flight: b 1s") || msg.contains("in flight: b 2s"),
        "expected ~1-2s elapsed for the stalled node, got: {msg}"
    );
    // Nodes that finished must NOT be reported as in flight.
    assert!(
        !msg.contains("in flight: a") && !msg.contains(", a "),
        "completed nodes must not be listed as in flight: {msg}"
    );
}

#[tokio::test]
async fn timeout_message_carries_no_node_config_or_output_content() {
    // DLP: node IDS and timings only. Node config values and node output
    // must never reach `error_message` / the digest preview / the
    // failure webhook through this path.
    let (graph_json, root_mod, a_mod, b_mod) = build_attribution_graph();
    let mut engine = engine_with_timeout(2, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(SelectiveSleepingDispatcher {
        slow_module: b_mod,
        delay: Duration::from_secs(30),
        slow_output_for: a_mod,
    });
    let err = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("workflow must time out");
    let msg = err.to_string();

    assert!(
        !msg.contains(CONFIG_CANARY),
        "node CONFIG leaked into the timeout message: {msg}"
    );
    assert!(
        !msg.contains(OUTPUT_CANARY),
        "node OUTPUT leaked into the timeout message: {msg}"
    );
    assert!(
        !msg.contains("qwen3.6"),
        "node config value leaked into the timeout message: {msg}"
    );
    // Sanity: the canaries really were wired in, so the assertions above
    // are not passing vacuously.
    let graph_text = serde_json::to_string(&graph_json).unwrap();
    assert!(graph_text.contains(CONFIG_CANARY));
}

#[tokio::test]
async fn timeout_before_any_dispatch_completes_reports_all_nodes_in_flight() {
    // Elapsed/count correctness at the other extreme: when the cap trips
    // before ANY node returns, the count is 0 and every dispatched node
    // is named.
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(1, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(SleepingDispatcher {
        delay: Duration::from_secs(30),
    });
    let err = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("workflow must time out");
    let msg = err.to_string();

    // Only `root` is dispatchable before its successors unblock.
    assert!(
        msg.contains("in flight: root "),
        "expected root named, got: {msg}"
    );
    assert!(
        msg.contains("0 nodes completed"),
        "nothing completed, got: {msg}"
    );
}

#[tokio::test]
async fn seeded_resume_path_also_attributes_the_timeout() {
    // The seeded path boxes the reactor future through a separate
    // wrapper; a regression there would silently drop attribution on
    // exactly the resume/crash-recovery runs where it is most useful.
    let (graph_json, root_mod, a_mod, b_mod) = build_attribution_graph();
    let mut engine = engine_with_timeout(2, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(SelectiveSleepingDispatcher {
        slow_module: b_mod,
        delay: Duration::from_secs(30),
        slow_output_for: a_mod,
    });
    let err = engine
        .run_with_seed_with_transport(
            dispatcher,
            None,
            std::collections::HashMap::new(),
            Uuid::new_v4(),
        )
        .await
        .expect_err("workflow must time out");
    let msg = err.to_string();
    assert!(
        msg.contains("in flight: b "),
        "seeded path lost attribution: {msg}"
    );
    assert!(msg.contains("2 nodes completed"), "got: {msg}");
}

#[tokio::test]
async fn a_reused_engine_does_not_report_the_previous_run_in_flight() {
    // The progress snapshot lives on the engine, so it must be reset per
    // run — otherwise a second run's timeout blames a node that belonged
    // to the first.
    let (graph_json, root_mod, a_mod, b_mod) = build_attribution_graph();
    let mut engine = engine_with_timeout(2, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(SelectiveSleepingDispatcher {
        slow_module: b_mod,
        delay: Duration::from_secs(30),
        slow_output_for: a_mod,
    });
    let first = engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect_err("first run times out");
    assert!(first.to_string().contains("2 nodes completed"));

    let second = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("second run times out");
    let msg = second.to_string();
    // Without a reset the counter would have carried over to 4.
    assert!(
        msg.contains("2 nodes completed"),
        "progress snapshot leaked across runs: {msg}"
    );
    assert_eq!(
        msg.matches("in flight: b ").count(),
        1,
        "node b must be listed once, not once per run: {msg}"
    );
}

#[tokio::test]
async fn node_timings_populated_on_fresh_runs() {
    // Post-unification property: WorkflowContext.node_timings used to
    // be empty on the fresh path and populated on the seeded path.
    // Both now populate it. Lock in the fresh-path side.
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(30, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(root_mod, json!({"output": "root"}))
            .with_response(a_mod, json!({"output": "a"}))
            .with_response(b_mod, json!({"output": "b"})),
    );
    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("workflow completes");

    // Every dispatched node should appear in node_timings. The fan-out
    // keeps all three on the single-node path (no chain consolidation).
    assert!(
        !ctx.node_timings.is_empty(),
        "node_timings should be populated on fresh runs"
    );
    assert_eq!(
        ctx.node_timings.len(),
        3,
        "all three nodes should have a timing entry"
    );
}
