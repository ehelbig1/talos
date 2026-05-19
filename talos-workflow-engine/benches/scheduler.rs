//! Microbenchmarks for the scheduler reactor.
//!
//! Goal: regression detection on scheduling overhead, *not* absolute
//! perf claims. The dispatcher is a no-op; numbers reflect the
//! reactor loop, chain detection, ready-queue management, and
//! futures-unordered orchestration — nothing about the worker pool,
//! transport, or wasm runtime.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p talos-workflow-engine
//! ```
//!
//! Add `--bench scheduler -- --quick` for a fast smoke run.
//!
//! Three families:
//!
//! * `fanout/N` — root → N parallel branches. Stresses
//!   `FuturesUnordered` + the per-node dispatch path.
//! * `chain/M` — root → step1 → … → stepM. Stresses linear-chain
//!   detection + the pipeline-batched dispatch path.
//! * `seeded_resume/S` — graph of S nodes resumed with all but the
//!   last seeded. Stresses the seed-propagation initialisation in
//!   `run_inner`.

use std::sync::Arc;

use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, DispatchJob, DispatchResult, NodeDispatcher, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use tokio::runtime::Runtime;
use uuid::Uuid;

/// Dispatcher that returns immediately. Strips dispatch latency out
/// of the measurement so the bench reflects scheduling overhead only.
struct NoopDispatcher;

#[async_trait]
impl NodeDispatcher for NoopDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult { output: json!({}) })
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

fn build_engine(modules: &[Uuid]) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    for &m in modules {
        fetcher = fetcher.with_module(m, stub_artifact(m));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine
}

/// Build a fan-out graph: `root` → N parallel leaves. Returns the
/// graph JSON plus the module ids (one per node, all distinct).
fn build_fanout(n: usize) -> (JsonValue, Vec<Uuid>) {
    let root_mod = Uuid::new_v4();
    let mut builder = WorkflowGraphBuilder::new().add_module("root", root_mod, None);
    let mut modules = vec![root_mod];
    for i in 0..n {
        let m = Uuid::new_v4();
        modules.push(m);
        builder = builder
            .add_module(format!("leaf-{i}"), m, None)
            .edge("root", format!("leaf-{i}"));
    }
    (builder.build().expect("graph builds"), modules)
}

/// Build a chain graph: 1 root + M sequential nodes after it. The
/// root fan-outs to a no-op leaf so chain detection sees `step1 →
/// step2 → … → stepM` as the chain (not the whole path) — keeps the
/// chain length parameter independent of the root.
///
/// Actually, simpler: pure linear `step0 → step1 → … → stepM-1`. The
/// chain detector batches the entire sequence in one
/// `dispatch_chain` call.
fn build_chain(m: usize) -> (JsonValue, Vec<Uuid>) {
    assert!(m >= 2, "chain bench requires at least 2 nodes");
    let mut builder = WorkflowGraphBuilder::new();
    let mut modules = Vec::with_capacity(m);
    for i in 0..m {
        let module_id = Uuid::new_v4();
        modules.push(module_id);
        builder = builder.add_module(format!("step-{i}"), module_id, None);
        if i > 0 {
            builder = builder.edge(format!("step-{}", i - 1), format!("step-{i}"));
        }
    }
    (builder.build().expect("graph builds"), modules)
}

fn bench_fanout(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("fanout");
    for &n in &[10usize, 100, 1000] {
        let (graph_json, modules) = build_fanout(n);
        let serialized = serde_json::to_string(&graph_json).expect("graph serializes");
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || {
                    // Fresh engine + dispatcher per iteration so we
                    // measure end-to-end scheduling, not warm-cache
                    // behavior on the global rate-limit map.
                    let mut engine = build_engine(&modules);
                    let dispatcher: Arc<dyn NodeDispatcher> = Arc::new(NoopDispatcher);
                    runtime
                        .block_on(engine.load_graph_from_json(&serialized))
                        .expect("graph loads");
                    (engine, dispatcher)
                },
                |(engine, dispatcher)| {
                    runtime
                        .block_on(engine.run_with_transport(dispatcher, None, Uuid::new_v4()))
                        .expect("workflow runs");
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_chain(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("chain");
    for &m in &[10usize, 100] {
        let (graph_json, modules) = build_chain(m);
        let serialized = serde_json::to_string(&graph_json).expect("graph serializes");
        group.throughput(Throughput::Elements(m as u64));
        group.bench_with_input(BenchmarkId::from_parameter(m), &m, |b, _| {
            b.iter_batched(
                || {
                    let mut engine = build_engine(&modules);
                    let dispatcher: Arc<dyn NodeDispatcher> = Arc::new(NoopDispatcher);
                    runtime
                        .block_on(engine.load_graph_from_json(&serialized))
                        .expect("graph loads");
                    (engine, dispatcher)
                },
                |(engine, dispatcher)| {
                    runtime
                        .block_on(engine.run_with_transport(dispatcher, None, Uuid::new_v4()))
                        .expect("workflow runs");
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_seeded_resume(c: &mut Criterion) {
    use std::collections::HashMap;
    let runtime = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("seeded_resume");
    for &s in &[10usize, 100, 1000] {
        let (graph_json, modules) = build_fanout(s);
        let serialized = serde_json::to_string(&graph_json).expect("graph serializes");
        group.throughput(Throughput::Elements(s as u64));
        group.bench_with_input(BenchmarkId::from_parameter(s), &s, |b, _| {
            b.iter_batched(
                || {
                    let mut engine = build_engine(&modules);
                    let dispatcher: Arc<dyn NodeDispatcher> = Arc::new(NoopDispatcher);
                    runtime
                        .block_on(engine.load_graph_from_json(&serialized))
                        .expect("graph loads");
                    // Seed everything except one leaf so the resume
                    // path has real work to do (one dispatch) but
                    // most of the bench cost is in seed propagation.
                    let mut seed: HashMap<Uuid, JsonValue> = HashMap::new();
                    let labels = engine.node_labels().clone();
                    for (id, label) in &labels {
                        if label != "leaf-0" {
                            seed.insert(*id, json!({"seeded": true}));
                        }
                    }
                    (engine, dispatcher, seed)
                },
                |(engine, dispatcher, seed)| {
                    runtime
                        .block_on(engine.run_with_seed_with_transport(
                            dispatcher,
                            None,
                            seed,
                            Uuid::new_v4(),
                        ))
                        .expect("resume runs");
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fanout, bench_chain, bench_seeded_resume);
criterion_main!(benches);
