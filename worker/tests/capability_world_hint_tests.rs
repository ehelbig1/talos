//! A module runs at the world it was dispatched at, never a wider one
//! (security review 2026-10-14, G-1).
//!
//! The dispatcher's `capability_world` hint is the module row's world — the
//! one the role gate, the actor ceiling and the dispatch ceiling checked.
//! Until this date a hint skipped inspection and NO hint linked whatever the
//! binary imported; several paths sent none. The runtime now inspects the
//! binary every time and refuses one whose world is wider than the hint,
//! before it is instantiated (`talos_wit_inspector::link_world`).
//!
//! The fixtures are real components built from WAT at test time, with the
//! world's metadata embedded the way `cargo component` embeds it, so the
//! inspector classifies them as it would a compiled module.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;
use talos_workflow_job_protocol::LlmTier;
use uuid::Uuid;
use worker::runtime::{RetryPolicy, SecurityPolicy, TalosRuntime};
use worker::wit_inspector::CapabilityWorld;

fn wit_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("wit")
        .join("talos.wit")
}

/// `run` logs once (to keep a `talos:core` import alive) and returns
/// `ok("{}")`.
const OK_CORE_WAT: &str = r#"
(module
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
    (i32.const 8)))
"#;

/// The same module, also importing `talos:core/secrets` (`release-slot`,
/// lowered as `(param i64 i32)`: a `u64` and the return-area pointer). It is
/// never called; the import is what makes the binary a secrets-node binary.
fn secrets_core_wat() -> String {
    OK_CORE_WAT.replacen(
        "(memory",
        "(import \"talos:core/secrets\" \"release-slot\" (func (param i64 i32)))\n  (memory",
        1,
    )
}

/// `core_wat` as a component of `world`.
fn component_of_world(world: &str, core_wat: &str) -> Vec<u8> {
    let mut core = wat::parse_str(core_wat).expect("core module WAT should parse");
    let mut resolve = wit_parser::Resolve::new();
    let (pkg, _files) = resolve
        .push_path(wit_path())
        .expect("wit/talos.wit should resolve");
    let world_id = resolve
        .select_world(pkg, Some(world))
        .expect("world should exist");
    wit_component::embed_component_metadata(
        &mut core,
        &resolve,
        world_id,
        wit_component::StringEncoding::UTF8,
    )
    .expect("embed world metadata");
    wit_component::ComponentEncoder::default()
        .validate(true)
        .module(&core)
        .expect("core module accepted by encoder")
        .encode()
        .expect("component should encode")
}

async fn run_with_hint(
    rt: &TalosRuntime,
    bytes: &[u8],
    hint: Option<CapabilityWorld>,
) -> anyhow::Result<serde_json::Value> {
    rt.execute_job_with_full_features(
        bytes,
        vec![],
        vec![],
        128,
        json!({}),
        None,
        None,
        HashMap::new(),
        None,
        Duration::from_secs(10),
        RetryPolicy::none(),
        None,
        SecurityPolicy::default(),
        hint,
        None,
        false,
        None,
        Uuid::nil(),
        LlmTier::Tier2,
        talos_workflow_job_protocol::WriteCeiling::Write,
        None,
        None,
        None,
        None,
        0,
        None,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_binary_wider_than_its_dispatched_world_is_refused() {
    let rt = TalosRuntime::new().expect("runtime");
    let secrets_binary = component_of_world("secrets-node", &secrets_core_wat());
    assert_eq!(
        worker::wit_inspector::inspect_component(&secrets_binary).capability_world,
        CapabilityWorld::Secrets,
        "fixture: the inspector reads this binary as secrets-node"
    );

    let err = run_with_hint(&rt, &secrets_binary, Some(CapabilityWorld::Minimal))
        .await
        .expect_err("a secrets binary dispatched at minimal must not run");
    assert!(
        format!("{err:#}").contains("capability-world-exceeded"),
        "{err:#}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_binary_within_its_dispatched_world_runs() {
    let rt = TalosRuntime::new().expect("runtime");
    let secrets_binary = component_of_world("secrets-node", &secrets_core_wat());
    let out = run_with_hint(&rt, &secrets_binary, Some(CapabilityWorld::Secrets))
        .await
        .expect("a secrets binary dispatched at secrets runs");
    assert!(out.is_object(), "{out}");

    let minimal_binary = component_of_world("minimal-node", OK_CORE_WAT);
    run_with_hint(&rt, &minimal_binary, Some(CapabilityWorld::Http))
        .await
        .expect("a minimal binary dispatched at a wider world runs at that world");
}
