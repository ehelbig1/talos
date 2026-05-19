//! `RateLimitStore` integration: a custom impl is consulted in place
//! of the in-memory default when wired via `set_rate_limit_store`.
//!
//! This test does NOT exercise the default in-memory behaviour
//! (covered by the existing engine unit tests). It locks in the
//! pluggability contract: a `set_rate_limit_store(Some(...))` call
//! makes the engine route every `check_rate_limit` through the trait
//! object; failure modes flow through the documented fail-open path.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{BoxError, RateLimitStore, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
    rate_limit::CountingRateLimitStore,
};
use uuid::Uuid;

/// Counts every call. Returns whatever the constructor asked for —
/// makes the rate-limited error envelope easy to elicit.
struct ScriptedRateLimitStore {
    next_count: AtomicU32,
    calls: Mutex<Vec<(Uuid, u64)>>,
    fail: bool,
}

impl ScriptedRateLimitStore {
    fn returning(count: u32) -> Self {
        Self {
            next_count: AtomicU32::new(count),
            calls: Mutex::new(Vec::new()),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            next_count: AtomicU32::new(0),
            calls: Mutex::new(Vec::new()),
            fail: true,
        }
    }

    fn call_log(&self) -> Vec<(Uuid, u64)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl RateLimitStore for ScriptedRateLimitStore {
    async fn record_and_count(&self, module_id: Uuid, window_secs: u64) -> Result<u32, BoxError> {
        self.calls.lock().unwrap().push((module_id, window_secs));
        if self.fail {
            return Err("rate-limit store unreachable".into());
        }
        Ok(self.next_count.load(Ordering::SeqCst))
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

/// Build a graph with a single module-backed node whose graph JSON
/// declares `rate_limit_per_minute = 5`. The node-config field is
/// what the engine reads at graph load time and stores in
/// `self.rate_limits` — without it, `check_rate_limit` early-returns
/// `None` and the store is never consulted.
fn graph_with_rate_limit(module_id: Uuid, limit_per_min: i32) -> serde_json::Value {
    let mut g = WorkflowGraphBuilder::new()
        .add_module("only", module_id, None)
        .build()
        .expect("graph builds");
    // Inject the rate-limit value via raw JSON — the typed builder
    // doesn't expose this knob (it's a low-traffic field; setter
    // doesn't pull its weight).
    if let Some(arr) = g.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        if let Some(node) = arr.first_mut().and_then(|v| v.as_object_mut()) {
            let data = node
                .entry("data")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .unwrap();
            data.insert("rate_limit_per_minute".into(), json!(limit_per_min));
        }
    }
    g
}

fn engine_for(module_id: Uuid) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(module_id, stub_artifact(module_id))
            // Important: the in-memory fetcher's load_rate_limits is
            // what populates `self.rate_limits`. The graph_json knob
            // alone won't trigger the check; the fetcher has to
            // surface the limit too. Use `with_rate_limit`.
            .with_rate_limit(module_id, 5),
    ));
    engine
}

#[tokio::test]
async fn custom_store_blocks_dispatch_when_count_exceeds_limit() {
    // Store returns count = 100 (well over the 5 limit). Engine
    // must produce an `__error: __rate_limit_exceeded` envelope and
    // not actually dispatch the module.
    let module_id = Uuid::new_v4();
    let mut engine = engine_for(module_id);
    let store = Arc::new(ScriptedRateLimitStore::returning(100));
    engine.set_rate_limit_store(store.clone());
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_with_rate_limit(module_id, 5)).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new().with_response(module_id, json!({"output": "would-have-run"})),
    );
    let ctx = engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect("workflow ok (rate-limited as a node-level error)");

    // The store must have been consulted exactly once for the one node.
    let log = store.call_log();
    assert_eq!(log.len(), 1, "store should have been called exactly once");
    assert_eq!(log[0].0, module_id);
    assert_eq!(log[0].1, 60, "engine passes 60s window");

    // The dispatcher MUST NOT have been called — the rate-limit gate
    // short-circuited before dispatch.
    assert_eq!(dispatcher.dispatch_count(module_id), 0);

    // The node's output is the rate-limit error envelope.
    let only_id = engine
        .node_labels()
        .iter()
        .find_map(|(id, label)| (label == "only").then_some(*id))
        .unwrap();
    let envelope = &ctx.results[&only_id];
    assert_eq!(envelope["__error"].as_bool(), Some(true));
    assert!(envelope["error_message"]
        .as_str()
        .unwrap_or("")
        .contains("rate limit"));
}

#[tokio::test]
async fn custom_store_allows_dispatch_when_count_below_limit() {
    // Store returns 1 (well under 5). Dispatch must proceed.
    let module_id = Uuid::new_v4();
    let mut engine = engine_for(module_id);
    engine.set_rate_limit_store(Arc::new(ScriptedRateLimitStore::returning(1)));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_with_rate_limit(module_id, 5)).unwrap())
        .await
        .expect("load");

    let dispatcher =
        Arc::new(ScriptedDispatcher::new().with_response(module_id, json!({"output": "ran"})));
    let ctx = engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect("ok");

    assert_eq!(dispatcher.dispatch_count(module_id), 1);
    let only_id = engine
        .node_labels()
        .iter()
        .find_map(|(id, label)| (label == "only").then_some(*id))
        .unwrap();
    // The dispatched output (not an error envelope) lands in results.
    let out = &ctx.results[&only_id];
    assert!(out.get("__error").and_then(|v| v.as_bool()).is_none());
}

#[tokio::test]
async fn store_failure_fails_open_and_dispatches() {
    // Store returns Err — documented fail-open behaviour: the engine
    // logs a warning and allows the dispatch. Critical for production
    // — a Redis blip must not block legitimate workflow execution.
    let module_id = Uuid::new_v4();
    let mut engine = engine_for(module_id);
    let store = Arc::new(ScriptedRateLimitStore::failing());
    engine.set_rate_limit_store(store.clone());
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_with_rate_limit(module_id, 5)).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new().with_response(module_id, json!({"output": "ran-anyway"})),
    );
    engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect("ok");

    // The store was consulted (proving the trait was called) and the
    // dispatcher ran (proving fail-open kicked in).
    assert_eq!(store.call_log().len(), 1);
    assert_eq!(dispatcher.dispatch_count(module_id), 1);
}

#[tokio::test]
async fn no_store_falls_back_to_in_memory_default() {
    // When no store is set, the engine routes through the
    // process-global DashMap. Sanity check that this path still
    // works and doesn't crash. Reset the global counter first so the
    // test is hermetic against other tests in the same binary.
    talos_workflow_engine::reset_global_rate_limits();

    let module_id = Uuid::new_v4();
    let mut engine = engine_for(module_id);
    // No set_rate_limit_store call — engine.rate_limit_store stays None.
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_with_rate_limit(module_id, 5)).unwrap())
        .await
        .expect("load");

    let dispatcher =
        Arc::new(ScriptedDispatcher::new().with_response(module_id, json!({"output": "ran"})));
    let _ = engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect("ok");

    assert_eq!(dispatcher.dispatch_count(module_id), 1);
}

#[tokio::test]
async fn counting_rate_limit_store_from_test_utils_records_calls() {
    // Validates that the test-utils CountingRateLimitStore is wired
    // through correctly — it's the recommended impl for downstream
    // integration tests, and a regression here would silently make
    // every consumer's metering invisible to their own assertions.
    let module_id = Uuid::new_v4();
    let mut engine = engine_for(module_id);
    let store = Arc::new(CountingRateLimitStore::new());
    engine.set_rate_limit_store(store.clone());
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_with_rate_limit(module_id, 5)).unwrap())
        .await
        .expect("load");

    let dispatcher =
        Arc::new(ScriptedDispatcher::new().with_response(module_id, json!({"output": "ran"})));
    let _ = engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await
        .expect("ok");

    // The engine consulted our store exactly once, and recorded
    // the dispatch.
    assert_eq!(store.call_count(), 1);
    assert_eq!(store.calls_for(module_id), 1);
    assert_eq!(store.current_count(module_id), 1);
    assert_eq!(dispatcher.dispatch_count(module_id), 1);
}
