//! RFC 0014 P2b, end to end through the engine: a job queued for the
//! local-inference slot does not spend the RUN's budget.
//!
//! The dispatcher here stands in for the NATS dispatcher's part: it reports the
//! job's (already verified) wait on the run clock the engine handed it in
//! `DispatchJob::run_waits`, exactly as `attempt_wait::await_attempt` does. What
//! this proves is the ENGINE's half — that both dispatch paths hand the run
//! clock over, and that the run's timeout honours what is reported on it. The
//! dispatcher's own half (verification, the attempt window) is tested in
//! `talos-workflow-engine-nats`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, DispatchJob, DispatchResult,
    NodeDispatcher, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

/// Queues for `queued` (reported on the run clock when `report` is on), then
/// works for `work`.
struct QueueingDispatcher {
    queued: Duration,
    work: Duration,
    report: bool,
    saw_run_clock: AtomicUsize,
}

fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

#[async_trait]
impl NodeDispatcher for QueueingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        let id = job.job_id.unwrap_or_else(Uuid::new_v4);
        if job.run_waits.is_some() {
            self.saw_run_clock.fetch_add(1, Ordering::SeqCst);
        }
        let clock = job.run_waits.clone().filter(|_| self.report);
        if let Some(c) = &clock {
            c.begin(id, now());
        }
        tokio::time::sleep(self.queued).await;
        if let Some(c) = &clock {
            c.end(id, now());
        }
        tokio::time::sleep(self.work).await;
        Ok(DispatchResult {
            output: json!({"output": "ok"}),
        })
    }

    async fn dispatch_chain(
        &self,
        _request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        unreachable!("the single-node path is taken")
    }
}

fn artifact(module_id: Uuid) -> WasmModuleArtifact {
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

async fn one_node_engine(budget_secs: u64) -> ParallelWorkflowEngine {
    let m = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("only", m, None)
        .build()
        .expect("graph");
    let mut engine = minimal_engine();
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(m, artifact(m)),
    ));
    engine.set_user_id(Uuid::new_v4());
    engine.set_execution_timeout_secs(budget_secs);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("graph loads");
    engine
}

/// A 30 s budget; the node queues 90 s then works 20 s. The run completes: its
/// budget stood still for the 90 s the job was queued behind other workflows.
#[tokio::test(start_paused = true)]
async fn a_queued_job_does_not_spend_the_runs_budget() {
    let engine = one_node_engine(30).await;
    let d = Arc::new(QueueingDispatcher {
        queued: Duration::from_secs(90),
        work: Duration::from_secs(20),
        report: true,
        saw_run_clock: AtomicUsize::new(0),
    });
    let started = tokio::time::Instant::now();
    let out = engine
        .run_with_transport(d.clone(), None, Uuid::new_v4())
        .await;
    assert!(out.is_ok(), "{:?}", out.err());
    assert_eq!(started.elapsed(), Duration::from_secs(110));
    assert_eq!(
        d.saw_run_clock.load(Ordering::SeqCst),
        1,
        "the single-node dispatch must carry the run clock"
    );
}

/// The control: the same run with the wait NOT reported times out at 30 s.
#[tokio::test(start_paused = true)]
async fn an_unreported_queue_still_spends_the_budget() {
    let engine = one_node_engine(30).await;
    let d = Arc::new(QueueingDispatcher {
        queued: Duration::from_secs(90),
        work: Duration::from_secs(20),
        report: false,
        saw_run_clock: AtomicUsize::new(0),
    });
    let started = tokio::time::Instant::now();
    let out = engine.run_with_transport(d, None, Uuid::new_v4()).await;
    assert!(matches!(
        out,
        Err(WorkflowEngineError::Timeout { secs: 30, .. })
    ));
    assert_eq!(started.elapsed(), Duration::from_secs(30));
}
