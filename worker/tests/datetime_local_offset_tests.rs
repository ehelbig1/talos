//! A guest can ask the host for a zone's UTC offset (2026-10-01).
//!
//! `datetime::local-offset-seconds` was added to the module interface so a
//! module can compute its owner's local date without a fixed offset in its
//! config. The pure function is unit-tested in the runtime crate; this drives
//! the WHOLE path — a real `minimal-node` component built from WAT, the
//! minimal-tier linker, the canonical-ABI lowering of
//! `func(zone: string, timestamp: u64) -> result<s32, error>` — because a
//! host function that is implemented but not linked, or lowered differently
//! from how a guest calls it, passes every unit test.
//!
//! It also covers the other direction: a component that imports the datetime
//! interface WITHOUT the new function (every module compiled before it
//! existed) still instantiates and runs.

use std::path::PathBuf;
use std::time::Duration;

use worker::runtime::TalosRuntime;

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

/// Calls `local-offset-seconds` three times and returns a three-letter JSON
/// string, one letter per call: `D` for -14400 (US Eastern daylight time),
/// `S` for -18000 (standard time), `X` for an error, `?` for anything else.
///
/// The function lowers to `(param ptr len ts retptr)`: the result's two flat
/// values do not fit one return value, so the host writes the discriminant at
/// `retptr` and the payload at `retptr + 4`.
///
/// Calls: New York on 2026-10-01 12:00 UTC, New York on 2026-12-01 12:00 UTC,
/// and a name that is not a zone.
const OFFSET_CORE_WAT: &str = r#"
(module
  (import "talos:core/datetime" "local-offset-seconds" (func $off (param i32 i32 i64 i32)))
  (memory (export "memory") 1)
  (data (i32.const 64) "America/New_York")
  (data (i32.const 96) "Not/AZone")
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
  (func $letter (param $ptr i32) (param $len i32) (param $ts i64) (result i32)
    (call $off (local.get $ptr) (local.get $len) (local.get $ts) (i32.const 128))
    (if (result i32) (i32.load8_u (i32.const 128))
      (then (i32.const 88))
      (else
        (if (result i32) (i32.eq (i32.load (i32.const 132)) (i32.const -14400))
          (then (i32.const 68))
          (else
            (if (result i32) (i32.eq (i32.load (i32.const 132)) (i32.const -18000))
              (then (i32.const 83))
              (else (i32.const 63))))))))
  (func (export "run") (param i32 i32) (result i32)
    (i32.store8 (i32.const 200) (i32.const 34))
    (i32.store8 (i32.const 201) (call $letter (i32.const 64) (i32.const 16) (i64.const 1790856000)))
    (i32.store8 (i32.const 202) (call $letter (i32.const 64) (i32.const 16) (i64.const 1796126400)))
    (i32.store8 (i32.const 203) (call $letter (i32.const 96) (i32.const 9) (i64.const 1790856000)))
    (i32.store8 (i32.const 204) (i32.const 34))
    (i32.store (i32.const 300) (i32.const 0))
    (i32.store (i32.const 304) (i32.const 200))
    (i32.store (i32.const 308) (i32.const 5))
    (i32.const 300)))
"#;

/// A module from before the function existed: it imports `now-unix` from the
/// same interface and nothing else. Returns `"ok"` when the clock is past
/// 2020, `"no"` otherwise.
const OLDER_GUEST_CORE_WAT: &str = r#"
(module
  (import "talos:core/datetime" "now-unix" (func $now (result i64)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
  (func (export "run") (param i32 i32) (result i32)
    (i32.store8 (i32.const 200) (i32.const 34))
    (if (i64.gt_u (call $now) (i64.const 1577836800))
      (then
        (i32.store8 (i32.const 201) (i32.const 111))
        (i32.store8 (i32.const 202) (i32.const 107)))
      (else
        (i32.store8 (i32.const 201) (i32.const 110))
        (i32.store8 (i32.const 202) (i32.const 111))))
    (i32.store8 (i32.const 203) (i32.const 34))
    (i32.store (i32.const 300) (i32.const 0))
    (i32.store (i32.const 304) (i32.const 200))
    (i32.store (i32.const 308) (i32.const 4))
    (i32.const 300)))
"#;

async fn run_guest(core_wat: &str) -> String {
    let rt = TalosRuntime::new().expect("runtime");
    let bytes = build_minimal_component(core_wat);
    let out = rt
        .execute_module_with_timeout(&bytes, "{}", Duration::from_secs(30))
        .await
        .unwrap_or_else(|e| panic!("guest failed: {e:#}"));
    out.to_string()
}

#[tokio::test]
async fn a_guest_gets_the_zones_offset_for_the_instant_it_asks_about() {
    let out = run_guest(OFFSET_CORE_WAT).await;
    // Daylight time in October, standard time in December, an error for a
    // name that is not a zone.
    assert!(out.contains("DSX"), "got {out}");
}

#[tokio::test]
async fn a_guest_compiled_before_the_function_existed_still_runs() {
    let out = run_guest(OLDER_GUEST_CORE_WAT).await;
    assert!(out.contains("ok"), "got {out}");
}
