//! The per-deployment switch that turns module compilation off
//! (`TALOS_MODULE_COMPILATION=false`).
//!
//! What must hold on such a deployment: no public entry point of the
//! compile service does ANY work — no workspace directory, no progress
//! event, no static-lint answer — and the refusal is recognisable as the
//! deployment's policy rather than as a toolchain failure.

use super::*;

const SOURCE: &str = "pub fn run(_input: String) -> Result<String, String> { Ok(String::new()) }";

/// A service with compilation off, its (empty) workspace root, and a
/// receiver that would see any progress event it emitted.
fn disabled_service() -> (
    CompilationService,
    tempfile::TempDir,
    tokio::sync::broadcast::Receiver<talos_engine_events::CompilationEvent>,
) {
    let root = tempfile::tempdir().expect("workspace root");
    let (event_tx, event_rx) = tokio::sync::broadcast::channel(8);
    let service = CompilationService::new(root.path().to_path_buf(), event_tx)
        .with_compilation_enabled(false);
    (service, root, event_rx)
}

fn assert_refused<T>(what: &str, outcome: Result<T>) {
    let error = match outcome {
        Ok(_) => panic!("{what} ran on a deployment with compilation off"),
        Err(error) => error,
    };
    assert!(
        is_compilation_disabled(&error),
        "{what} failed for another reason: {error:#}"
    );
    assert_eq!(
        caller_facing_service_error(&error),
        COMPILATION_DISABLED_MESSAGE
    );
}

#[tokio::test]
async fn every_public_entry_point_refuses_before_doing_any_work() {
    let (service, root, mut events) = disabled_service();
    assert!(!service.compilation_enabled());
    let user = Uuid::new_v4();
    let config = serde_json::json!({});

    assert_refused(
        "compile_to_wasm_with_config",
        service
            .compile_to_wasm_with_config(user, Uuid::new_v4(), "m", SOURCE, &config, None)
            .await,
    );
    for language in [
        None,
        Some(ModuleLanguage::Rust),
        Some(ModuleLanguage::JavaScript),
        Some(ModuleLanguage::Python),
        Some(ModuleLanguage::TypeScript),
        Some(ModuleLanguage::Go),
    ] {
        assert_refused(
            "compile_to_wasm_with_language",
            service
                .compile_to_wasm_with_language(
                    user,
                    Uuid::new_v4(),
                    "m",
                    SOURCE,
                    &config,
                    None,
                    language,
                )
                .await,
        );
    }
    assert_refused(
        "compile_js_to_wasm",
        service
            .compile_js_to_wasm("export function run() {}", "minimal-node", "job")
            .await,
    );
    assert_refused(
        "compile_python_to_wasm",
        service
            .compile_python_to_wasm("def run(i): return i", "minimal-node", "job")
            .await,
    );
    // Source with a static-lint ERROR: the pre-pass answers that without a
    // slot on an enabled deployment, so it is the case that would leak work
    // past a refusal placed only at the slot.
    assert_refused(
        "lint_code",
        service
            .lint_code(
                Some(user),
                "m",
                "fn f() { let _ = std::process::Command::new(\"ls\"); }",
                "minimal-node",
                None,
            )
            .await,
    );
    assert_refused("analyze_code", service.analyze_code("m", SOURCE).await);

    assert!(
        std::fs::read_dir(root.path()).unwrap().next().is_none(),
        "a refused request created a workspace"
    );
    assert!(
        events.try_recv().is_err(),
        "a refused request emitted a progress event"
    );
}

/// The slot is the guarantee: an entry point added later that forgets the
/// up-front check still cannot obtain one.
#[tokio::test]
async fn the_slot_itself_is_refused() {
    let (service, _root, _events) = disabled_service();
    assert_refused("acquire_slot", service.acquire_slot().await);
}

#[tokio::test]
async fn an_enabled_service_hands_out_a_slot() {
    let root = tempfile::tempdir().unwrap();
    let (event_tx, _rx) = tokio::sync::broadcast::channel(8);
    let service =
        CompilationService::new(root.path().to_path_buf(), event_tx).with_compilation_enabled(true);
    assert!(service.acquire_slot().await.is_ok());
}

#[test]
fn the_refusal_survives_context_and_nothing_else_is_mistaken_for_it() {
    let wrapped = anyhow::Error::new(CompilationDisabled)
        .context("compile_catalog_template(json-api-reader)")
        .context("seeding the catalog");
    assert!(is_compilation_disabled(&wrapped));
    assert_eq!(
        caller_facing_service_error(&wrapped),
        COMPILATION_DISABLED_MESSAGE
    );

    let toolchain = anyhow::anyhow!("cargo exited 101: /app/talos/target/…");
    assert!(!is_compilation_disabled(&toolchain));
    assert_eq!(
        caller_facing_service_error(&toolchain),
        COMPILATION_SERVICE_ERROR_MESSAGE
    );
}

/// `CompileSlot::acquire` is how a slot is made, and a slot is the only
/// thing that lets a sandbox child start. The service must obtain one in
/// exactly one place, behind the switch.
#[test]
fn the_service_obtains_a_slot_in_exactly_one_place_behind_the_switch() {
    let acquire = ["CompileSlot", "::acquire("].concat();
    for (file, source) in [
        ("lib.rs", include_str!("lib.rs")),
        ("analyze.rs", include_str!("analyze.rs")),
        ("target_cache.rs", include_str!("target_cache.rs")),
        ("catalog.rs", include_str!("catalog.rs")),
        ("scaffold.rs", include_str!("scaffold.rs")),
        ("advisory_db.rs", include_str!("advisory_db.rs")),
    ] {
        let expected = usize::from(file == "lib.rs");
        assert_eq!(
            source.matches(&acquire).count(),
            expected,
            "{file}: a compile slot is obtained outside CompilationService::acquire_slot"
        );
    }
    let lib = include_str!("lib.rs");
    let body_start = lib
        .find("async fn acquire_slot(&self)")
        .expect("acquire_slot exists");
    let body = &lib[body_start..];
    let body = &body[..body.find("\n    }\n").expect("acquire_slot ends")];
    let gate = body
        .find("self.ensure_enabled()?")
        .expect("acquire_slot checks the switch");
    let made = body.find(&acquire).expect("acquire_slot makes the slot");
    assert!(gate < made, "the switch is checked after the slot is made");
}
