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
//!     interrupt (driven by the runtime's own ticker thread) preempts the same tight
//!     loop. This is the ONLY mechanism that can stop a non-yielding loop
//!     that a `tokio::time::timeout` alone cannot.
//!  3. `cancellation_aborts_http_promptly` — a cancelled execution's
//!     outbound HTTP host call short-circuits immediately instead of
//!     dialing the network.
//!  3b. `cancellation_preempts_a_compute_bound_module` — the COMPUTE-BOUND
//!     half of the same guarantee: a guest that makes no host call after
//!     entry reaches none of the ~20 `is_cancelled()` guards, and used to
//!     burn its whole timeout. The epoch-deadline callback
//!     (`talos_worker_runtime::epoch_budget`) re-reads the same flag and
//!     traps it out of its loop. Its sibling
//!     `an_uncancelled_compute_bound_job_still_traps_at_its_own_budget`
//!     is the regression guard: with no cancel, the SAME module on the
//!     SAME path must still trap near its configured timeout, with the
//!     ordinary trap message and not the cancellation one.
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
    // The runtime's own epoch ticker is the hang-proof backstop: fuel (10M ≈
    // 25ms) fires long before the epoch deadline, but if it somehow didn't,
    // epoch caps the test at the 30s deadline instead of hanging the suite.
    let bytes = build_minimal_component(LOOP_CORE_WAT);

    let start = std::time::Instant::now();
    let res = rt
        .execute_module_with_timeout(&bytes, "{}", Duration::from_secs(30))
        .await;
    let elapsed = start.elapsed();

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
    // epoch-deadline interrupt (driven by the runtime's own ticker thread)
    // can stop the tight loop. Hold FUEL_ENV_LOCK across the set→new→remove so the
    // override can't leak into a parallel test's runtime construction.
    let rt = {
        let _g = FUEL_ENV_LOCK.lock().unwrap();
        std::env::set_var("WASM_FUEL_LIMIT", "1000000000000"); // 1e12 instructions
        let rt = TalosRuntime::new().expect("runtime");
        std::env::remove_var("WASM_FUEL_LIMIT");
        rt
    };

    // No ticker is started here: since 2026-09-25 `TalosRuntime`'s
    // constructor starts it, so a runtime built the way the CONTROLLER builds
    // one (which never started a ticker before) is covered too.

    let bytes = build_minimal_component(LOOP_CORE_WAT);
    let start = std::time::Instant::now();
    // This path (`..._with_context_and_timeout`) sets the store's epoch
    // deadline from the passed timeout, so epoch trips at ~2s.
    let (res, _logs) = rt.execute_test_module_string(&bytes, "{}").await;
    let elapsed = start.elapsed();

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
// (2b) Wall-clock bounds that hold in the CONTROLLER's runtime too
// ============================================================================
//
// The controller builds its own `TalosRuntime` (run_sandbox, test_module,
// scratch sessions, module replay) and, until 2026-09-25, never started an
// epoch ticker — only `worker/src/main.rs` did. These tests build the runtime
// exactly as the controller does (`TalosRuntime::new()`, nothing else) and
// assert a bounded return. They run the guest on a SEPARATE thread with its
// own runtime and wait with `recv_timeout`, because a regression here does not
// fail — it spins forever, and neither an in-test `tokio::time::timeout` nor
// the test harness can preempt a guest that never yields.

/// Run `f` on its own OS thread and return its result, or fail the test if it
/// has not finished within `limit`. On failure the spinning thread is leaked,
/// which is the point: it is the evidence that nothing preempted the guest.
fn finish_within<T: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(v) => v,
        Err(_) => panic!(
            "{what}: did not return within {limit:?} — the guest was not preempted \
             (no epoch ticker, or the epoch callback does not yield)"
        ),
    }
}

/// A current-thread runtime, the harshest case: one executor thread shared by
/// the guest and everything else.
fn current_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// `run` writes a 1,000,000-byte JSON string literal (`"aaa…a"`) into its
/// memory — just under the host's 1 MiB `WASM_MAX_JSON_SIZE` cap, so every
/// call really parses rather than being refused at the size check (the first
/// draft was 2 bytes over, and measured a WARN-log loop instead) — then calls
/// the `json::parse` host function on it forever. Each iteration costs a
/// few fuel (three constants, a call, a branch) — the host's parse costs no
/// fuel at all — so the DEFAULT 10M-fuel budget allows on the order of a
/// million host parses. Measured with no ticker: still running at this test's
/// 30 s watchdog. Fuel is not a wall-clock bound for host work; only the epoch
/// is.
///
/// (The fill that builds the string is charged its 1 MiB in fuel once, up
/// front: wasmtime 47 prices a bulk-memory op by its length, which is why this
/// fixture does NOT loop on `memory.fill` — that exhausts fuel in milliseconds
/// and would prove nothing.)
///
/// `parse: func(json-str: string) -> result<_, error>` lowers to
/// `(param ptr len retptr)`: the result's two flat values exceed the one-value
/// limit, so the host writes them through the return pointer (bytes 0..8).
const HOST_PARSE_LOOP_CORE_WAT: &str = r#"
(module
  (import "talos:core/json" "parse" (func $parse (param i32 i32 i32)))
  (memory (export "memory") 32)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32)
    (memory.fill (i32.const 16) (i32.const 97) (i32.const 999998))
    (i32.store8 (i32.const 15) (i32.const 34))
    (i32.store8 (i32.const 1000014) (i32.const 34))
    (loop $l
      (call $parse (i32.const 15) (i32.const 1000000) (i32.const 0))
      (br $l))
    (unreachable)))
"#;

/// The defect this closes: a runtime built the way the CONTROLLER builds one
/// had no epoch ticker, so a guest looping on a CPU-bound host call under the
/// DEFAULT fuel budget held its thread past a 30 s watchdog. With the ticker
/// owned by the constructor it is stopped near its 2 s timeout.
#[test]
fn a_host_call_loop_under_default_fuel_is_bounded_by_wall_clock() {
    let rt = {
        let _g = FUEL_ENV_LOCK.lock().unwrap();
        std::env::remove_var("WASM_FUEL_LIMIT");
        TalosRuntime::new().expect("runtime")
    };
    let bytes = build_minimal_component(HOST_PARSE_LOOP_CORE_WAT);
    let (res, elapsed) = finish_within(
        Duration::from_secs(30),
        "json::parse host-call loop",
        move || {
            let tokio_rt = current_thread_rt();
            let start = std::time::Instant::now();
            let res = tokio_rt.block_on(rt.execute_module_with_timeout(
                &bytes,
                "{}",
                Duration::from_secs(2),
            ));
            (res.map_err(|e| format!("{e:#}")), start.elapsed())
        },
    );
    let err = res.expect_err("an endless host-call loop must not return Ok");
    // Anti-vacuity: the loop must have been stopped by the CLOCK. A fuel trap
    // or an instantiation failure would also be an `Err`, and would make this
    // test pass without exercising the ticker at all — which is exactly how
    // its first draft (a `memory.fill` loop) passed on a tree with no ticker.
    assert!(
        !err.contains("fuel"),
        "the loop must be stopped by the wall clock, not by fuel: {err}"
    );
    assert!(
        err.contains("timed out") || err.contains("interrupt"),
        "expected a wall-clock stop, got: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "the loop must be stopped near its 2 s timeout (elapsed {elapsed:?})"
    );
}

/// The `Yield` half. The guest's OWN deadline is 30 s (the
/// `execute_module_string` default) and fuel is effectively infinite; the
/// caller's 1 s `tokio::time::timeout` can only fire if the guest's future
/// returns `Pending`. A `Continue` epoch extension never does, so the outer
/// timeout would wait for the 30 s deadline and a sibling task on the same
/// thread would not run at all. With `Yield` the heartbeat keeps beating and
/// the outer timeout wins within about a tick.
#[test]
fn a_compute_bound_guest_yields_its_thread_to_the_executor() {
    let rt = {
        let _g = FUEL_ENV_LOCK.lock().unwrap();
        std::env::set_var("WASM_FUEL_LIMIT", "1000000000000"); // 1e12 instructions
        let rt = TalosRuntime::new().expect("runtime");
        std::env::remove_var("WASM_FUEL_LIMIT");
        rt
    };
    let bytes = build_minimal_component(LOOP_CORE_WAT);
    let (timed_out, elapsed, beats) = finish_within(
        Duration::from_secs(20),
        "outer timeout around a busy guest",
        move || {
            let tokio_rt = current_thread_rt();
            tokio_rt.block_on(async move {
                let beats = Arc::new(AtomicUsize::new(0));
                let heartbeat = {
                    let beats = beats.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            beats.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                };
                let start = std::time::Instant::now();
                let outcome = tokio::time::timeout(
                    Duration::from_secs(1),
                    rt.execute_module_string(&bytes, "{}"),
                )
                .await;
                let elapsed = start.elapsed();
                heartbeat.abort();
                (outcome.is_err(), elapsed, beats.load(Ordering::Relaxed))
            })
        },
    );
    assert!(
        timed_out,
        "the caller's 1 s timeout must win over the guest's 30 s deadline"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the outer timeout must fire within about a tick of 1 s (elapsed {elapsed:?})"
    );
    assert!(
        beats >= 5,
        "a sibling task on the same thread must keep running while the guest computes \
         (heartbeat beat {beats} times in {elapsed:?})"
    );
}

/// A component whose `run` returns `ok("{}")` at once, padded with `n` unused
/// functions so its Cranelift compile takes real time. The padding functions
/// are exported so dead-code elimination cannot drop them.
fn big_ok_component(n: usize) -> Vec<u8> {
    let mut wat = String::from(
        r#"(module
  (import "talos:core/logging" "log" (func $log (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 200))
  (func (export "run") (param i32 i32) (result i32)
    (call $log (i32.const 1) (i32.const 0) (i32.const 0))
    (i32.store8 (i32.const 100) (i32.const 123))
    (i32.store8 (i32.const 101) (i32.const 125))
    (i32.store (i32.const 8) (i32.const 0))
    (i32.store (i32.const 12) (i32.const 100))
    (i32.store (i32.const 16) (i32.const 2))
    (i32.const 8))
"#,
    );
    for i in 0..n {
        wat.push_str(&format!(
            "  (func (export \"pad{i}\") (param i32) (result i32)\n"
        ));
        wat.push_str("    (local i32)\n");
        for k in 0..40 {
            wat.push_str(&format!(
                "    (local.set 1 (i32.add (i32.mul (local.get 0) (i32.const {})) (local.get 1)))\n",
                k + 3
            ));
        }
        wat.push_str("    (local.get 1))\n");
    }
    wat.push(')');
    build_minimal_component(&wat)
}

/// A cache-miss compile must not hold the executor thread. Cranelift codegen
/// for a large component is pure CPU; until 2026-09-25 it ran inline in the
/// async execution path, so on the controller — whose runtime serves requests
/// — every other task on that thread stalled for the whole compile. It now
/// runs under `spawn_blocking`, so a heartbeat on the SAME current-thread
/// runtime keeps beating while the module compiles.
#[test]
fn a_cache_miss_compile_does_not_hold_the_executor_thread() {
    let rt = TalosRuntime::new().expect("runtime");
    let bytes = big_ok_component(3_000);
    let (res, elapsed, beats) = finish_within(
        Duration::from_secs(300),
        "large component compile",
        move || {
            let tokio_rt = current_thread_rt();
            tokio_rt.block_on(async move {
                let beats = Arc::new(AtomicUsize::new(0));
                let heartbeat = {
                    let beats = beats.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            beats.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                };
                // Let the heartbeat start before the compile begins.
                tokio::task::yield_now().await;
                let start = std::time::Instant::now();
                let res = rt
                    .execute_module_with_timeout(&bytes, "{}", Duration::from_secs(120))
                    .await;
                let elapsed = start.elapsed();
                heartbeat.abort();
                (
                    res.map_err(|e| format!("{e:#}")),
                    elapsed,
                    beats.load(Ordering::Relaxed),
                )
            })
        },
    );
    res.expect("the padded component must compile and run");
    // Anti-vacuity: a compile too fast to measure proves nothing either way.
    assert!(
        elapsed >= Duration::from_millis(200),
        "the fixture must take measurable compile time to be a test at all ({elapsed:?}); \
         raise the padding"
    );
    let expected_beats = (elapsed.as_millis() / 10) as usize;
    assert!(
        beats * 4 >= expected_beats,
        "the executor thread must keep scheduling other tasks during a compile: \
         {beats} heartbeats in {elapsed:?} (~{expected_beats} if never blocked)"
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
        None, // egress_scope: tier-derived default
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
        max_retries: 0,
        retry_backoff_ms: 0,
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
            None, // http_verb_ceiling — inherit the ceiling above
            None, // egress_scope: tier default
            None, // llm_usage_out — not collected in kill-switch tests
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
            None, // http_verb_ceiling — inherit the ceiling above
            None, // egress_scope: tier default
            None, // llm_usage_out — not collected in kill-switch tests
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
            None, // http_verb_ceiling — inherit the ceiling above
            None, // egress_scope: tier default
            None, // llm_usage_out — not collected in kill-switch tests
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

// ============================================================================
// (3b) Cancellation preempts a COMPUTE-BOUND module
// ============================================================================

/// A tight loop making no host calls, cancelled mid-flight, on the real
/// single-node job path.
///
/// This is the case #690 could not reach. `LOOP_CORE_WAT` calls
/// `logging.log` exactly once (to pin the import against dead-code
/// elimination) and then spins forever — after that first call it crosses no
/// host-call boundary again, so every one of the ~20 `is_cancelled()` guards
/// is unreachable to it. Before the epoch-deadline callback the flag could be
/// set and nothing would read it; the job held its worker slot for the full
/// `JOB_TIMEOUT`.
///
/// Both other kill switches are deliberately disarmed so neither can be
/// mistaken for the mechanism under test:
///   * fuel — overridden to 1e12 instructions, unreachable in seconds;
///   * wall-clock — `JOB_TIMEOUT` is 60 s and the assertion is that the job
///     dies in a small fraction of that. (`tokio::time::timeout` could not
///     fire here anyway: a non-yielding sync loop inside `call_async` never
///     returns to the executor. That is precisely why epochs exist.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_preempts_a_compute_bound_module() {
    use talos_workflow_job_protocol::LlmTier;
    use uuid::Uuid;

    /// Long enough that a job dying near it would be a TIMEOUT, not a cancel.
    const JOB_TIMEOUT: Duration = Duration::from_secs(60);
    /// Effectively infinite — fuel must not be the limiter.
    const HUGE_FUEL: u64 = 1_000_000_000_000;

    // The epoch ticker is started by the runtime's constructor.
    let rt = Arc::new(TalosRuntime::new().expect("runtime"));

    let execution_id = Uuid::new_v4();
    let bytes = build_minimal_component(LOOP_CORE_WAT);

    let job = {
        let rt = rt.clone();
        let execution_id = execution_id.to_string();
        tokio::spawn(async move {
            rt.execute_job_with_full_features(
                &bytes,
                vec![],
                vec![],
                128,
                serde_json::json!({}),
                None,
                // Element 0 is the workflow_executions.id — what an operator
                // cancels, and what `cancel_registry` keys on.
                Some((
                    execution_id,
                    Uuid::new_v4().to_string(),
                    "oci://loop".to_string(),
                )),
                HashMap::new(),
                None,
                JOB_TIMEOUT,
                worker::runtime::RetryPolicy::none(),
                None,
                SecurityPolicy::default(),
                None,            // capability_world_hint — let it inspect
                Some(HUGE_FUEL), // max_fuel_override
                false,           // dry_run
                None,            // actor_id
                Uuid::nil(),     // user_id
                LlmTier::Tier2,
                talos_workflow_job_protocol::WriteCeiling::Write,
                None, // http_verb_ceiling — inherit the ceiling above
                None, // egress_scope
                None, // llm_usage_out
                None, // host_diag_out
                0,    // dispatch_attempt
            )
            .await
        })
    };

    // Wait for the job to REGISTER before cancelling. Cancelling earlier would
    // flag nothing (a 0 return is the normal miss outcome) and the test would
    // silently degrade into the timeout case it is meant to exclude.
    let registered = tokio::time::timeout(Duration::from_secs(20), async {
        while rt.in_flight_cancellable_jobs() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        registered.is_ok(),
        "the job never registered as in-flight; nothing was cancelled"
    );

    // Let the guest get properly into its loop, so the abort is a genuine
    // mid-computation preemption rather than a race against instantiation.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let cancel_at = std::time::Instant::now();
    let flagged = rt.cancel_execution(execution_id);
    assert_eq!(flagged, 1, "the cancel must reach exactly this job's flag");

    let res = tokio::time::timeout(Duration::from_secs(20), job)
        .await
        .expect("the cancelled job must not run to the 60s timeout")
        .expect("job task panicked");
    let elapsed = cancel_at.elapsed();

    let err = format!("{:#}", res.expect_err("a preempted job must not return Ok"));

    assert!(
        err.contains("cancelled"),
        "a preempted job must report the cancellation, got: {err}"
    );
    // Requirement: distinguishable from a genuine timeout and from fuel.
    let lower = err.to_lowercase();
    assert!(
        !lower.contains("timed out") && !lower.contains("timeout"),
        "an operator kill must not read as a wall-clock timeout: {err}"
    );
    assert!(
        !lower.contains("fuel"),
        "an operator kill must not read as fuel exhaustion: {err}"
    );
    assert!(
        !err.contains("WASM trap encountered"),
        "the abort must survive the generic trap sanitiser: {err}"
    );
    // The controller must not re-dispatch it, and the worker must not retry
    // it. Both gates key on this token: the worker's
    // `is_transient_error_text` (pinned by `epoch_budget`'s
    // `the_abort_message_classifies_non_transient`) and the controller's
    // `talos_retry_intelligence::classify_error` (pinned by that crate's
    // `every_reason_class_token_maps_to_the_right_bucket`). Asserting the
    // TOKEN here rather than re-running a classifier keeps this test free of
    // a dependency on the controller-side crate.
    assert!(
        err.contains("[reason_class=cancelled]"),
        "a preempted job must carry the non-transient cancelled reason class: {err}"
    );

    // The mechanism, not the timeout: one epoch tick is 100 ms, so a working
    // preemption lands in well under a second. 10 s is six times the slowest
    // plausible CI scheduling delay and still six times below the 60 s budget.
    assert!(
        elapsed < Duration::from_secs(10),
        "preemption must follow the cancel promptly, not at the job timeout \
         (elapsed {elapsed:?})"
    );

    assert_eq!(
        rt.in_flight_cancellable_jobs(),
        0,
        "the registry must drain when the preempted job unwinds"
    );
}

/// The regression guard for the other half of the change: an UNCANCELLED job
/// must be unable to tell the difference.
///
/// Same module, same path, same disarmed fuel — but no cancel. The sliced
/// epoch budget must still add up to the original one, so the loop dies near
/// its configured timeout (not before it, and not appreciably after), with the
/// ordinary trap message rather than the cancellation one. A bug that let the
/// slices grow without bound would hang here instead of failing an assert,
/// which is why the outer `tokio::time::timeout` is well above the budget
/// rather than snug against it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uncancelled_compute_bound_job_still_traps_at_its_own_budget() {
    use talos_workflow_job_protocol::LlmTier;
    use uuid::Uuid;

    const JOB_TIMEOUT: Duration = Duration::from_secs(3);
    const HUGE_FUEL: u64 = 1_000_000_000_000;

    let rt = TalosRuntime::new().expect("runtime");
    let bytes = build_minimal_component(LOOP_CORE_WAT);

    let start = std::time::Instant::now();
    let res = rt
        .execute_job_with_full_features(
            &bytes,
            vec![],
            vec![],
            128,
            serde_json::json!({}),
            None,
            Some((
                Uuid::new_v4().to_string(),
                Uuid::new_v4().to_string(),
                "oci://loop".to_string(),
            )),
            HashMap::new(),
            None,
            JOB_TIMEOUT,
            worker::runtime::RetryPolicy::none(),
            None,
            SecurityPolicy::default(),
            None,
            Some(HUGE_FUEL),
            false,
            None,
            Uuid::nil(),
            LlmTier::Tier2,
            talos_workflow_job_protocol::WriteCeiling::Write,
            None, // http_verb_ceiling — inherit the ceiling above
            None,
            None,
            None,
            0, // dispatch_attempt
        )
        .await;
    let elapsed = start.elapsed();

    let err = format!("{:#}", res.expect_err("a runaway loop must not return Ok"));
    assert!(
        !err.contains("cancelled"),
        "an uncancelled job must not be reported as cancelled: {err}"
    );
    // `epoch_ticks_for_timeout` rounds UP, so the trap may not land BEFORE the
    // configured timeout — only at or after it. That contract is unchanged by
    // the slicing.
    assert!(
        elapsed >= JOB_TIMEOUT.saturating_sub(Duration::from_millis(200)),
        "the epoch budget must not be spent early (elapsed {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "the sliced budget must still sum to the original one, not extend it \
         (elapsed {elapsed:?}, budget {JOB_TIMEOUT:?})"
    );
}
