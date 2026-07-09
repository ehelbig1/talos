//! End-to-end kill-switch integration tests.
//!
//! These prove the guarantees the whole sandbox design leans on — that an
//! untrusted (or buggy) WASM module CANNOT run away, hang a shutdown, or
//! starve the worker:
//!
//!  1. `fuel_exhaustion_kills_runaway_loop` — a tight infinite loop is
//!     stopped by wasmtime fuel metering under the pooling allocator.
//!  2. `epoch_interruption_kills_runaway_loop_with_huge_fuel` — with fuel
//!     set absurdly high so it can't be the limiter, the epoch-deadline
//!     interrupt (driven by `spawn_epoch_ticker`) preempts the same tight
//!     loop. This is the ONLY mechanism that can stop a non-yielding loop
//!     that a `tokio::time::timeout` alone cannot.
//!  3. `cancellation_aborts_http_promptly` — a cancelled execution's
//!     outbound HTTP host call short-circuits immediately instead of
//!     dialing the network.
//!  4. `pipeline_mid_step_failure_propagates` — a trapping middle step
//!     aborts the pipeline; later steps never run and the error surfaces.
//!  5. `concurrency_semaphore_queues_never_drops` — the semaphore the
//!     job-dispatch loop relies on admits at most N concurrently and
//!     queues the rest; every task completes (none dropped).
//!
//! The runaway-loop / trap / ok fixtures are real `minimal-node`
//! components built from WAT at test time (see `build_minimal_component`)
//! so the tests exercise the true instantiate → fuel/epoch → trap path,
//! not a mock.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use worker::context::TalosContext;
use worker::expose_fallback::ExposeFallback;
use worker::runtime::{PipelineStepSpec, SecurityPolicy, TalosRuntime};
use worker::wit_inspector::CapabilityWorld;

// ============================================================================
// Fixture builders
// ============================================================================

fn wit_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("wit")
        .join("talos.wit")
}

/// Encode a core module as a `minimal-node` component.
///
/// Embeds the `minimal-node` world metadata so the worker's
/// `wit_inspector` classifies it as `Minimal` and the minimal-tier linker
/// satisfies the (logging) import. The core module MUST keep at least one
/// live `talos:core/*` import (we call `logging.log`) so the import
/// survives dead-code elimination — otherwise the component has an empty
/// import section and is classified `Unknown` (rejected up front).
fn build_minimal_component(core_wat: &str) -> Vec<u8> {
    let mut core = wat::parse_str(core_wat).expect("core module WAT should parse");
    let mut resolve = wit_parser::Resolve::new();
    let (pkg, _files) = resolve
        .push_path(wit_path())
        .expect("wit/talos.wit should resolve");
    let world = resolve
        .select_world(pkg, Some("minimal-node"))
        .expect("minimal-node world should exist");
    wit_component::embed_component_metadata(
        &mut core,
        &resolve,
        world,
        wit_component::StringEncoding::UTF8,
    )
    .expect("embed minimal-node metadata");
    wit_component::ComponentEncoder::default()
        .validate(true)
        .module(&core)
        .expect("core module accepted by encoder")
        .encode()
        .expect("component should encode")
}

/// `run` calls `logging.log` once (to pin the import) then loops forever.
const LOOP_CORE_WAT: &str = r#"
(module
  (import "talos:core/logging" "log" (func $log (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32)
    (call $log (i32.const 1) (i32.const 0) (i32.const 0))
    (loop $l (br $l))
    (unreachable)))
"#;

/// `run` calls `logging.log` once (to pin the import) then traps.
const TRAP_CORE_WAT: &str = r#"
(module
  (import "talos:core/logging" "log" (func $log (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32)
    (call $log (i32.const 1) (i32.const 0) (i32.const 0))
    (unreachable)))
"#;

/// `run` returns `err("boom")` — the `result<string,string>` Err arm
/// (tag=1). This is a module SIGNALLING failure (vs. trapping), which the
/// pipeline surfaces as `Pipeline step '<id>' returned error: boom`.
const ERR_CORE_WAT: &str = r#"
(module
  (import "talos:core/logging" "log" (func $log (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 200))
  (func (export "run") (param i32 i32) (result i32)
    (i32.store8 (i32.const 100) (i32.const 98))  ;; 'b'
    (i32.store8 (i32.const 101) (i32.const 111)) ;; 'o'
    (i32.store8 (i32.const 102) (i32.const 111)) ;; 'o'
    (i32.store8 (i32.const 103) (i32.const 109)) ;; 'm'
    (i32.store (i32.const 8) (i32.const 1))       ;; tag = err
    (i32.store (i32.const 12) (i32.const 100))    ;; str ptr
    (i32.store (i32.const 16) (i32.const 4))      ;; str len "boom"
    (i32.const 8)))
"#;

/// `run` returns `ok("{}")` — writes the `result<string,string>` return
/// area (tag=0 ok, ptr, len) and the two-byte JSON string "{}". The
/// pipeline path parses each step's output as JSON, so the payload must be
/// valid JSON (not a bare word).
const OK_CORE_WAT: &str = r#"
(module
  (import "talos:core/logging" "log" (func $log (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 200))
  (func (export "run") (param i32 i32) (result i32)
    (i32.store8 (i32.const 100) (i32.const 123)) ;; '{'
    (i32.store8 (i32.const 101) (i32.const 125)) ;; '}'
    (i32.store (i32.const 8) (i32.const 0))       ;; tag = ok
    (i32.store (i32.const 12) (i32.const 100))    ;; str ptr
    (i32.store (i32.const 16) (i32.const 2))      ;; str len
    (i32.const 8)))
"#;

/// Serialises the two tests that read (and one that mutates) the global
/// `WASM_FUEL_LIMIT` env var at `TalosRuntime::new()` time. Cargo runs
/// tests in one process on many threads, so without this the epoch test's
/// `set_var` could race into the fuel test's runtime construction and make
/// the fuel test's loop un-exhaustible (a 300s hang under the tokio
/// timeout, which cannot preempt a tight loop). Held across `new()`.
static FUEL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ============================================================================
// (1) Fuel exhaustion
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fuel_exhaustion_kills_runaway_loop() {
    // Construct the runtime with the DEFAULT fuel limit — hold the env lock
    // and clear any override so a parallel test's `WASM_FUEL_LIMIT` mutation
    // can't leak in and make the loop un-exhaustible.
    let rt = {
        let _g = FUEL_ENV_LOCK.lock().unwrap();
        std::env::remove_var("WASM_FUEL_LIMIT");
        TalosRuntime::new().expect("runtime")
    };
    // Epoch ticker as a hang-proof backstop: fuel (10M ≈ 25ms) fires long
    // before the epoch deadline, but if it somehow didn't, epoch caps the
    // test at the 30s deadline instead of hanging the suite.
    let ticker = worker::runtime::spawn_epoch_ticker(rt.engine_handle());
    let bytes = build_minimal_component(LOOP_CORE_WAT);

    let start = std::time::Instant::now();
    let res = rt
        .execute_module_with_timeout(&bytes, "{}", Duration::from_secs(30))
        .await;
    let elapsed = start.elapsed();
    ticker.abort();

    assert!(res.is_err(), "a runaway loop must not return Ok");
    let err = format!("{:#}", res.unwrap_err());
    assert!(
        err.contains("fuel"),
        "runaway loop should be killed by fuel exhaustion, got: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "fuel should trip fast, not near the wall-clock timeout (elapsed {elapsed:?})"
    );
}

// ============================================================================
// (2) Epoch interruption (independent of fuel)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn epoch_interruption_kills_runaway_loop_with_huge_fuel() {
    // Fuel set absurdly high so it CANNOT be the limiter — only the
    // epoch-deadline interrupt (driven by the ticker below) can stop the
    // tight loop. Hold FUEL_ENV_LOCK across the set→new→remove so the
    // override can't leak into a parallel test's runtime construction.
    let rt = {
        let _g = FUEL_ENV_LOCK.lock().unwrap();
        std::env::set_var("WASM_FUEL_LIMIT", "1000000000000"); // 1e12 instructions
        let rt = TalosRuntime::new().expect("runtime");
        std::env::remove_var("WASM_FUEL_LIMIT");
        rt
    };

    // Epoch interruption is inert without a ticker incrementing the engine
    // epoch — this is the exact wiring `main.rs` does at startup.
    let ticker = worker::runtime::spawn_epoch_ticker(rt.engine_handle());

    let bytes = build_minimal_component(LOOP_CORE_WAT);
    let start = std::time::Instant::now();
    // This path (`..._with_context_and_timeout`) sets the store's epoch
    // deadline from the passed timeout, so epoch trips at ~2s.
    let (res, _logs) = rt.execute_test_module_string(&bytes, "{}").await;
    let elapsed = start.elapsed();
    ticker.abort();

    assert!(
        res.is_err(),
        "a runaway loop must be killed even with effectively-infinite fuel"
    );
    // `execute_test_module_string` uses a 10s internal timeout; epoch must
    // fire at or before that, and crucially the process must not hang.
    assert!(
        elapsed < Duration::from_secs(20),
        "epoch interrupt must stop the loop near its deadline (elapsed {elapsed:?})"
    );
}

// ============================================================================
// (3) Cancellation mid-HTTP aborts promptly
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_aborts_http_promptly() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};

    let mut ctx = make_http_context();

    // Cancel BEFORE the fetch — the host fn must observe the flag and
    // refuse to dial out. A public, resolvable host with a long timeout is
    // used so that if the cancel check were missing, the test would hang
    // on the network instead of returning fast.
    ctx.cancel();
    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://example.com/".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: Some(30_000),
    };

    let start = std::time::Instant::now();
    let res = ctx.fetch(req).await;
    let elapsed = start.elapsed();

    assert!(
        matches!(res, Err(wit_http::Error::Networkerror)),
        "a cancelled execution's fetch must abort, got: {res:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "cancellation must short-circuit before the network call (elapsed {elapsed:?})"
    );
}

/// An HTTP-world context with a wildcard host allowlist and Tier-2
/// (external egress) — mirrors the sibling suites' `make_context()`.
fn make_http_context() -> TalosContext {
    TalosContext::new(
        CapabilityWorld::Http,
        vec!["*".to_string()],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(ExposeFallback::new()),
        talos_workflow_job_protocol::LlmTier::Tier2,
    )
    .expect("context")
}

// ============================================================================
// (4) Pipeline mid-step failure propagates
// ============================================================================

fn pipeline_step(id: &str, bytes: Vec<u8>) -> PipelineStepSpec {
    PipelineStepSpec {
        module_id: id.to_string(),
        wasm_bytes: bytes,
        config: serde_json::Value::Null,
        allowed_hosts: vec![],
        allowed_methods: vec![],
        secrets: HashMap::new(),
        max_fuel: 10_000_000,
        max_memory_mb: 64,
        timeout: Duration::from_secs(10),
        security_policy: SecurityPolicy::default(),
        user_id: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_mid_step_failure_propagates() {
    let rt = TalosRuntime::new().expect("runtime");
    let ok_bytes = build_minimal_component(OK_CORE_WAT);
    let err_bytes = build_minimal_component(ERR_CORE_WAT);

    // step1 ok → step2 signals err("boom") → step3 ok. The pipeline must
    // abort AT step2: the surfaced error names step2 (not step3), which
    // proves step3 never ran — if it had, the error would carry step3's id
    // or the pipeline would have succeeded.
    let steps = vec![
        pipeline_step("step1-ok", ok_bytes.clone()),
        pipeline_step("step2-err", err_bytes),
        pipeline_step("step3-ok", ok_bytes),
    ];

    let res = rt
        .execute_pipeline(
            "test-exec-pipeline-err",
            steps,
            Duration::from_secs(30),
            false,
            talos_workflow_job_protocol::LlmTier::Tier2,
            talos_workflow_job_protocol::WriteCeiling::Write,
        )
        .await;

    let err = match res {
        Err(e) => format!("{e:#}"),
        Ok(_) => panic!("an erroring middle step must fail the whole pipeline"),
    };
    assert!(
        err.contains("step2-err"),
        "the failure must name the offending step (proving step3 never ran), got: {err}"
    );
    assert!(
        !err.contains("step3-ok"),
        "step3 must not appear — it must never have executed, got: {err}"
    );
    assert!(
        err.contains("boom"),
        "the module's own error message must propagate, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_mid_step_trap_propagates() {
    // A trapping (not erroring) middle step is the harder failure mode:
    // it surfaces as a raw wasm trap. We assert the pipeline aborts and
    // never reaches the final ok step (which would have produced a "{}"
    // success output).
    let rt = TalosRuntime::new().expect("runtime");
    let ok_bytes = build_minimal_component(OK_CORE_WAT);
    let trap_bytes = build_minimal_component(TRAP_CORE_WAT);

    let steps = vec![
        pipeline_step("step1-ok", ok_bytes.clone()),
        pipeline_step("step2-trap", trap_bytes),
        pipeline_step("step3-ok", ok_bytes),
    ];

    let res = rt
        .execute_pipeline(
            "test-exec-pipeline-trap",
            steps,
            Duration::from_secs(30),
            false,
            talos_workflow_job_protocol::LlmTier::Tier2,
            talos_workflow_job_protocol::WriteCeiling::Write,
        )
        .await;

    assert!(
        res.is_err(),
        "a trapping middle step must fail the whole pipeline, not silently continue"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_all_steps_ok_succeeds() {
    // Control case: two ok steps run to completion and both outputs are
    // recorded — proves the failure test above isn't passing vacuously.
    let rt = TalosRuntime::new().expect("runtime");
    let ok_bytes = build_minimal_component(OK_CORE_WAT);

    let res = rt
        .execute_pipeline(
            "test-exec-pipeline-ok",
            vec![
                pipeline_step("s1", ok_bytes.clone()),
                pipeline_step("s2", ok_bytes),
            ],
            Duration::from_secs(30),
            false,
            talos_workflow_job_protocol::LlmTier::Tier2,
            talos_workflow_job_protocol::WriteCeiling::Write,
        )
        .await
        .expect("all-ok pipeline should succeed");

    assert_eq!(
        res.step_outputs.len(),
        2,
        "both steps should have produced output"
    );
}

// ============================================================================
// (5) Concurrency-cap saturation: jobs queue, none dropped
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrency_semaphore_queues_never_drops() {
    // This models the exact primitive the job-dispatch loop in `main.rs`
    // relies on: a `Semaphore` sized to the concurrency cap, from which
    // each job acquires a permit before running. The guarantee under test:
    // at saturation, excess jobs QUEUE on `acquire()` (they don't error or
    // get dropped), never more than `cap` run at once, and every job
    // eventually completes.
    const CAP: usize = 8;
    const TOTAL_JOBS: usize = 40;

    let sem = Arc::new(tokio::sync::Semaphore::new(CAP));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(TOTAL_JOBS);
    for _ in 0..TOTAL_JOBS {
        let sem = sem.clone();
        let in_flight = in_flight.clone();
        let max_in_flight = max_in_flight.clone();
        let completed = completed.clone();
        handles.push(tokio::spawn(async move {
            // acquire_owned mirrors the dispatch loop's `acquire_owned()`.
            let _permit = sem.acquire_owned().await.expect("semaphore not closed");
            let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            // Track the high-water mark of concurrent holders.
            max_in_flight.fetch_max(cur, Ordering::SeqCst);
            // Simulate work so contention actually builds up.
            tokio::time::sleep(Duration::from_millis(20)).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            completed.fetch_add(1, Ordering::SeqCst);
        }));
    }

    for h in handles {
        h.await.expect("no job task should panic or be dropped");
    }

    assert_eq!(
        completed.load(Ordering::SeqCst),
        TOTAL_JOBS,
        "every queued job must complete — none dropped"
    );
    assert!(
        max_in_flight.load(Ordering::SeqCst) <= CAP,
        "never more than the cap ({CAP}) should run concurrently, saw {}",
        max_in_flight.load(Ordering::SeqCst)
    );
    assert_eq!(
        sem.available_permits(),
        CAP,
        "all permits must be returned after drain (clean back-pressure)"
    );
}
