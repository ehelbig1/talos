//! Env-gated proof that the REAL shipped catalog templates compile through
//! the REAL production path — `CatalogTemplate::load` +
//! `CompilationService::compile_catalog_template`, the exact pair the disk
//! seeder calls at every controller boot.
//!
//! ```bash
//! TALOS_TEST_CATALOG_COMPILE=1 cargo test -p talos-compilation \
//!     --test catalog_template_compile -- --nocapture
//! ```
//!
//! # Why this exists
//!
//! `make check-catalog` scaffolds its own crate. It is a good gate for the
//! TEMPLATES, and a useless one for the RUNTIME — between 2026-07 and
//! 2026-08-11 it was green on a tree where the controller failed three of
//! these templates on every single boot, because the runtime passed
//! `dependencies: None` and the script read the manifest. A script that
//! reimplements the manifest can never catch that class; only calling the
//! production API can.
//!
//! So this test asserts the one thing the script structurally cannot: that
//! `compile_catalog_template` produces real WASM for a template whose source
//! needs a crate its `talos.json` declares. Run against the pre-fix tree it
//! fails with `use of unresolved module or unlinked crate`.
//!
//! Scope, stated rather than implied: it compiles ONLY the templates that
//! declare a dependency (the class that broke), not all 75 — three real WASM
//! builds is already minutes. Full-catalog coverage is `make check-catalog`'s
//! job, and the two are complementary, not redundant.
//!
//! # The byte counts this prints are NOT a fingerprint
//!
//! The `<slug>: N bytes, hash H` lines below are diagnostic output for a
//! human reading `--nocapture`, and nothing asserts on them. They are not
//! reproducible: two consecutive runs on the same tree and toolchain gave
//! 120339/106586/141471 and 120338/106586/141470, with a DIFFERENT
//! `content_hash` every time (the artifacts embed build-varying data). The
//! assertion here is deliberately `bytes.len() > 1024` — "real WASM came
//! out", which is the property that was false before 2026-08-11 — and it
//! must stay that shape. Do not tighten it to an expected size, and do not
//! quote a run's numbers anywhere as if they identified a build; a specific
//! figure is one sample of a distribution, not an identity.

// ci-ungated: runs real `cargo component build`s and needs the HOST
// cargo-component toolchain plus the wasm32-wasip2 target — minutes per
// template. Requires TALOS_TEST_CATALOG_COMPILE=1. The non-compiling half of
// this property (talos.json is the only declaration production reads) IS
// gated, in `scripts/check-catalog.sh` leg 2 and in
// `talos_compilation::catalog`'s unit tests.

use std::path::{Path, PathBuf};

#[tokio::test]
async fn dependency_declaring_templates_compile_via_the_production_path() {
    if std::env::var("TALOS_TEST_CATALOG_COMPILE").is_err() {
        eprintln!("skipping: set TALOS_TEST_CATALOG_COMPILE=1 to run real compiles");
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module-templates");
    assert!(
        root.is_dir(),
        "module-templates not found at {} — update this test rather than \
         letting it pass over zero templates",
        root.display()
    );
    // The compile service resolves the SDK proc-macro crate from
    // `/app/talos_sdk_macros` (the image path) unless told otherwise.
    std::env::set_var(
        "TALOS_SDK_MACROS_PATH",
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../talos_sdk_macros")
            .canonicalize()
            .expect("talos_sdk_macros must exist"),
    );
    std::env::set_var("TALOS_COMPILATION_CONTAINER", "false");
    std::env::set_var("RUST_ENV", "development");

    // Every template whose talos.json declares an extra crate — i.e. exactly
    // the population the dependency-plumbing bug could break. Discovered, not
    // hardcoded: a new dependency-declaring template is covered automatically.
    let mut subjects: Vec<(String, talos_compilation::CatalogTemplate)> = Vec::new();
    for entry in std::fs::read_dir(&root)
        .expect("read module-templates")
        .flatten()
    {
        let dir = entry.path();
        if !dir.is_dir() || !dir.join("talos.json").exists() {
            continue;
        }
        let Ok(t) = talos_compilation::CatalogTemplate::load(&dir) else {
            continue;
        };
        if t.dependencies().is_some() {
            subjects.push((
                dir.file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or_default()
                    .to_string(),
                t,
            ));
        }
    }
    subjects.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(
        !subjects.is_empty(),
        "no template declares dependencies — either the catalog changed or \
         CatalogTemplate::dependencies stopped reading the manifest; a green \
         run over zero subjects proves nothing"
    );
    eprintln!(
        "compiling {} dependency-declaring template(s): {}",
        subjects.len(),
        subjects
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let workspaces = tempfile::tempdir().expect("workspace root");
    let (event_tx, _rx) = tokio::sync::broadcast::channel(64);
    let svc =
        talos_compilation::CompilationService::new(PathBuf::from(workspaces.path()), event_tx);

    for (slug, template) in subjects {
        let result = svc
            .compile_catalog_template(uuid::Uuid::nil(), uuid::Uuid::new_v4(), &slug, &template)
            .await
            .unwrap_or_else(|e| panic!("{slug}: compile_catalog_template errored: {e:#}"));

        assert!(
            result.success,
            "{slug}: production compile path failed — this is the boot-time \
             failure the seeder hits. Declared deps: {:?}. Errors: {:#?}",
            template.dependencies(),
            result.errors
        );
        let bytes = result
            .wasm_bytes
            .unwrap_or_else(|| panic!("{slug}: success with no WASM bytes"));
        assert!(
            bytes.len() > 1024,
            "{slug}: implausibly small artifact ({} bytes)",
            bytes.len()
        );
        eprintln!(
            "  {slug}: {} bytes, hash {}",
            bytes.len(),
            result.content_hash
        );
    }
}
