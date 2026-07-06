//! Env-gated integration proof for the per-user persistent target cache.
//!
//! Runs REAL `cargo component build`s (host toolchain: cargo-component +
//! wasm32-wasip2 target required), so it no-ops under a plain `cargo test`
//! and only runs when explicitly requested:
//!
//! ```bash
//! TALOS_TEST_COMPILE_CACHE=1 cargo test -p talos-compilation \
//!     --test target_cache_integration -- --nocapture
//! ```
//!
//! Asserts the mechanism, prints the measurement: a user's second compile
//! (different source, same deps) reuses the cached dependency artifacts and
//! must be substantially faster than their cold first compile. The timing
//! assertion is deliberately loose (warm < 60% of cold) — the point is
//! "deps were reused", not a benchmark number.

use std::path::PathBuf;

const SOURCE_A: &str = r#"
use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let parsed: serde_json::Value = serde_json::from_str(&input).unwrap_or_default();
    Ok(serde_json::json!({ "echo": parsed, "variant": "a" }).to_string())
}
"#;

const SOURCE_B: &str = r#"
use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let parsed: serde_json::Value = serde_json::from_str(&input).unwrap_or_default();
    let n = parsed.get("n").and_then(|v| v.as_i64()).unwrap_or(0);
    Ok(serde_json::json!({ "doubled": n * 2, "variant": "b" }).to_string())
}
"#;

#[tokio::test]
async fn second_compile_for_same_user_is_warm() {
    if std::env::var("TALOS_TEST_COMPILE_CACHE").is_err() {
        eprintln!("skipping: set TALOS_TEST_COMPILE_CACHE=1 to run real compiles");
        return;
    }

    let workspaces = tempfile::tempdir().expect("workspace root");
    let cache_root = tempfile::tempdir().expect("cache root");

    // Host-direct cargo (the dev path); per-user cache rooted in a temp dir
    // so the test is hermetic and never touches /tmp/cargo-target.
    std::env::set_var("TALOS_COMPILATION_CONTAINER", "false");
    std::env::set_var("TALOS_COMPILE_TARGET_CACHE_DIR", cache_root.path());
    std::env::set_var("RUST_ENV", "development");

    let (event_tx, _rx) = tokio::sync::broadcast::channel(64);
    let svc =
        talos_compilation::CompilationService::new(PathBuf::from(workspaces.path()), event_tx);

    let user = uuid::Uuid::new_v4();

    let t0 = std::time::Instant::now();
    let cold = svc
        .compile_to_wasm(user, uuid::Uuid::new_v4(), "cache-probe-a", SOURCE_A)
        .await
        .expect("cold compile ran");
    let cold_elapsed = t0.elapsed();
    assert!(cold.success, "cold compile must succeed: {:?}", cold.errors);

    let user_cache = cache_root.path().join(user.to_string());
    assert!(
        user_cache.join("wasm32-wasip2").exists(),
        "cold compile must populate the per-user target cache"
    );

    let t1 = std::time::Instant::now();
    let warm = svc
        .compile_to_wasm(user, uuid::Uuid::new_v4(), "cache-probe-b", SOURCE_B)
        .await
        .expect("warm compile ran");
    let warm_elapsed = t1.elapsed();
    assert!(warm.success, "warm compile must succeed: {:?}", warm.errors);
    assert_ne!(
        cold.content_hash, warm.content_hash,
        "distinct sources must produce distinct artifacts (no stale reuse)"
    );

    eprintln!(
        "cold: {:.1}s  warm: {:.1}s  ({}x)",
        cold_elapsed.as_secs_f64(),
        warm_elapsed.as_secs_f64(),
        (cold_elapsed.as_secs_f64() / warm_elapsed.as_secs_f64().max(0.001)).round()
    );
    assert!(
        warm_elapsed < cold_elapsed.mul_f64(0.6),
        "warm compile ({warm_elapsed:?}) should be well under 60% of cold ({cold_elapsed:?}) — \
         dependency artifacts were not reused"
    );
}
