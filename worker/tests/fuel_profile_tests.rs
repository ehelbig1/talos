//! A rehearsal can ask where a run's fuel went (2026-10-03).
//!
//! The profile's arithmetic is unit-tested in `talos-worker-runtime`. This
//! drives the part a unit test cannot: a real component, the real linker, the
//! wasmtime call hook reading the store's fuel at each guest↔host transition,
//! and a host function naming itself. A hook that is never installed, or a
//! host function that never sets its label, passes every unit test.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use talos_workflow_job_protocol::LlmTier;
use uuid::Uuid;
use worker::runtime::{RetryPolicy, SecurityPolicy, TalosRuntime};

fn build_minimal_component(core_wat: &str) -> Vec<u8> {
    let mut core = wat::parse_str(core_wat).expect("core module WAT should parse");
    let mut resolve = wit_parser::Resolve::new();
    let wit = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("wit")
        .join("talos.wit");
    let (pkg, _files) = resolve
        .push_path(wit)
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

/// Burns a little fuel, asks the host for the time, burns fifty times as
/// much, and returns `"ok"`. The two loops are the same code, so the ratio of
/// the fuel charged to each is the ratio of their iteration counts.
const BURN_CORE_WAT: &str = r#"
(module
  (import "talos:core/datetime" "now-unix" (func $now (result i64)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
  (func $burn (param $n i32)
    (local $i i32)
    (loop $again
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $again (i32.lt_u (local.get $i) (local.get $n)))))
  (func (export "run") (param i32 i32) (result i32)
    (call $burn (i32.const 1000))
    (drop (call $now))
    (call $burn (i32.const 50000))
    (i32.store8 (i32.const 200) (i32.const 34))
    (i32.store8 (i32.const 201) (i32.const 111))
    (i32.store8 (i32.const 202) (i32.const 107))
    (i32.store8 (i32.const 203) (i32.const 34))
    (i32.store (i32.const 300) (i32.const 0))
    (i32.store (i32.const 304) (i32.const 200))
    (i32.store (i32.const 308) (i32.const 4))
    (i32.const 300)))
"#;

async fn run(policy: SecurityPolicy) -> (String, u64) {
    let rt = TalosRuntime::new().expect("runtime");
    let fuel = worker::context::FuelAcc::default();
    let out = rt
        .execute_job_with_full_features(
            &build_minimal_component(BURN_CORE_WAT),
            vec![],
            vec![],
            128,
            json!({}),
            None,
            None,
            std::collections::HashMap::new(),
            None,
            Duration::from_secs(30),
            RetryPolicy::none(),
            None,
            policy,
            None,                                             // capability_world_hint
            None,                                             // max_fuel_override
            false,                                            // dry_run
            None,                                             // actor_id
            Uuid::nil(),                                      // user_id
            LlmTier::Tier2,                                   // max_llm_tier
            talos_workflow_job_protocol::WriteCeiling::Write, // max_write_ceiling
            None,                                             // http_verb_ceiling
            None,                                             // egress_scope
            None,                                             // llm_usage_out
            None,                                             // host_diag_out
            0,                                                // dispatch_attempt
            None,                                             // inference_wait
            Some(fuel.clone()),                               // fuel_out
        )
        .await
        .unwrap_or_else(|e| panic!("guest failed: {e:#}"));
    let consumed = fuel
        .lock()
        .unwrap()
        .expect("the run measured its fuel")
        .consumed;
    (out.to_string(), consumed)
}

#[tokio::test]
async fn the_profile_charges_fuel_to_the_host_call_it_followed() {
    let profile = Arc::new(worker::fuel_profile::FuelProfile::new());
    let (out, consumed) = run(SecurityPolicy {
        fuel_profile: Some(profile.clone()),
        ..Default::default()
    })
    .await;
    assert!(out.contains("ok"), "got {out}");

    let report = profile.report();
    let stretch = |after: &str| {
        report
            .guest
            .iter()
            .find(|g| g.after == after)
            .unwrap_or_else(|| panic!("no stretch after {after}: {report:?}"))
            .fuel
    };
    let before = stretch(worker::fuel_profile::START);
    let after = stretch("datetime::now-unix");
    assert!(before >= 1000, "the first loop ran 1000 times: {report:?}");
    assert!(
        after > before * 20,
        "the second loop is fifty times the first, so the fuel after the host \
         call must dwarf the fuel before it: {report:?}"
    );
    // The host function named itself, and was called once.
    assert_eq!(report.host_calls.len(), 1, "{report:?}");
    assert_eq!(report.host_calls[0].call, "datetime::now-unix");
    assert_eq!(report.host_calls[0].count, 1);
    // Every unit the run consumed is on exactly one row.
    assert_eq!(report.accounted, consumed, "{report:?}");
}

/// Control: a run that did not ask for a profile consumes the same fuel. The
/// hook observes; it does not charge.
#[tokio::test]
async fn asking_for_a_profile_does_not_change_the_fuel_a_run_uses() {
    let (_, plain) = run(SecurityPolicy::default()).await;
    let profile = Arc::new(worker::fuel_profile::FuelProfile::new());
    let (_, profiled) = run(SecurityPolicy {
        fuel_profile: Some(profile),
        ..Default::default()
    })
    .await;
    assert_eq!(plain, profiled);
}
