//! Env-gated integration proof for the sandboxed JS/Python compile paths
//! (M-13 wiring). Runs REAL `jco componentize` / `componentize-py` compiles
//! inside the talos-builder container, so it needs Docker (or podman) and a
//! locally-built `talos-builder:latest` (`make builder-image`). No-ops under
//! a plain `cargo test`:
//!
//! ```bash
//! TALOS_TEST_JSPY_SANDBOX=1 cargo test -p talos-compilation \
//!     --test jspy_sandbox_integration -- --nocapture --test-threads=1
//! ```
//!
//! What this pins:
//! * the container invocation shape (relative args + `-w /build`) produces a
//!   valid component for BOTH toolchains against the repo's real talos.wit;
//! * the Python SDK shim (module-level `run` → `WitWorld`) compiles;
//! * `--network=none` holds — the tools need no fetch at componentize time.

const PY_SDK_SHAPED: &str = r#"
import json

def run(input: str) -> str:
    data = json.loads(input) if input else {}
    return json.dumps({"echo": data, "lang": "python"})
"#;

const JS_SOURCE: &str = r#"
// @talos-world: minimal-node
export function run(input) {
  const data = input ? JSON.parse(input) : {};
  return JSON.stringify({ echo: data, lang: "javascript" });
}
"#;

fn service() -> talos_compilation::CompilationService {
    let (event_tx, _rx) = tokio::sync::broadcast::channel(64);
    let root = std::env::temp_dir().join("talos-jspy-sandbox-test");
    std::fs::create_dir_all(&root).expect("workspace root");
    talos_compilation::CompilationService::new(root, event_tx)
}

fn gated() -> bool {
    if std::env::var("TALOS_TEST_JSPY_SANDBOX").is_err() {
        eprintln!("skipping: set TALOS_TEST_JSPY_SANDBOX=1 (needs docker + talos-builder:latest)");
        return false;
    }
    // Force the sandbox path — the whole point of the test.
    std::env::set_var("TALOS_COMPILATION_CONTAINER", "true");
    true
}

#[tokio::test]
async fn python_sdk_shaped_source_compiles_in_sandbox() {
    if !gated() {
        return;
    }
    let svc = service();
    let wasm = svc
        .compile_python_to_wasm(
            PY_SDK_SHAPED,
            "minimal-node",
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .expect("sandboxed python compile");
    assert!(&wasm[..4] == b"\0asm", "must be a wasm binary");
    assert!(
        wasm.len() > 1_000_000,
        "componentize-py output embeds CPython — a tiny output means it compiled the wrong thing"
    );
    eprintln!("python component: {} bytes", wasm.len());
}

#[tokio::test]
async fn javascript_compiles_in_sandbox_via_language_router() {
    if !gated() {
        return;
    }
    let svc = service();
    let result = svc
        .compile_to_wasm_with_language(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "jspy-sandbox-js",
            JS_SOURCE,
            &serde_json::json!({}),
            None,
            Some(talos_compilation::ModuleLanguage::JavaScript),
        )
        .await
        .expect("sandboxed js compile ran");
    assert!(
        result.success,
        "js compile must succeed: {:?}",
        result.errors
    );
    let wasm = result.wasm_bytes.expect("wasm bytes");
    assert!(&wasm[..4] == b"\0asm");
    eprintln!("js component: {} bytes", wasm.len());
}

#[tokio::test]
async fn python_compile_error_is_surfaced_not_swallowed() {
    if !gated() {
        return;
    }
    let svc = service();
    let err = svc
        .compile_python_to_wasm(
            "def run(input:  # unterminated",
            "minimal-node",
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .expect_err("syntactically-broken python must fail the compile");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Python compilation failed"),
        "error must carry the toolchain failure context, got: {msg}"
    );
}
