//! A catalog template's declared fuel limit, checked against a recorded run.
//!
//! ```bash
//! make check-catalog-fuel                    # every template with fixtures
//! make check-catalog-fuel TEMPLATE=<slug>    # one, while promoting it
//! ```
//!
//! # What this is for
//!
//! A shared catalog row is sized from its manifest's `recommended_fuel`
//! (`talos_compilation::recommended_max_fuel`, the one reader both catalog
//! writers use). That number is an author's estimate, and an estimate was all
//! it could be: the only way to learn what a module costs was to run it on a
//! platform. A template promoted from the authoring lane arrives with the
//! recorded responses it was rehearsed against (`fixtures/`), so the estimate
//! can be checked before the template is published.
//!
//! For every template that carries `fixtures/http.json`, this test
//!
//! 1. builds the module through the production compile path
//!    (`CatalogTemplate::load` + `CompilationService::compile_catalog_template`,
//!    the pair the boot seed and the registry publisher call),
//! 2. runs it once in the worker runtime, answered from the recorded
//!    responses — nothing is sent (`talos_worker_runtime::http_replay`),
//! 3. requires the run to succeed and to use every recorded response, and
//! 4. requires the fuel it used to stay under
//!    `HIGH_FUEL_UTILISATION` of the limit the manifest declares — the same
//!    line the platform's own headroom detector draws, so a template cannot
//!    be published already inside it.
//!
//! It prints the measured figure for each template (and writes it to the
//! job summary on CI), which is the number to size `recommended_fuel` from.
//!
//! # What it does not prove
//!
//! One recorded run is one payload. The limit is honest for a response of
//! that size and shape, and says nothing about a larger one — state in the
//! fixture's README what the recording represents. Fuel is deterministic for
//! one build of one source on one payload; it is NOT stable across compiler
//! versions, so nothing here asserts an exact figure.

// ci-ungated: builds real WASM through the HOST cargo-component toolchain
// (minutes on a cold cache) and needs the wasm32-wasip2 target, so it cannot
// run in the DB-free unit job. Requires TALOS_TEST_CATALOG_FUEL=1; the
// `catalog` job in quality.yml runs it through `make check-catalog-fuel`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use talos_compilation::scaffold::HIGH_FUEL_UTILISATION;
use talos_worker_runtime::http_replay::HttpReplay;
use talos_worker_runtime::runtime::{RetryPolicy, SecurityPolicy, TalosRuntime};
use talos_workflow_job_protocol::{EgressScope, LlmTier, WriteCeiling};

/// What a template's `fixtures/` directory holds.
struct Recording {
    slug: String,
    template: talos_compilation::CatalogTemplate,
    config: serde_json::Value,
    input: serde_json::Value,
    /// Hosts the rehearsal may "reach", for a template whose manifest grants
    /// none (the installer supplies them). Rehearsal only: nothing is sent.
    extra_hosts: Vec<String>,
    http: serde_json::Value,
}

struct Measured {
    slug: String,
    consumed: u64,
    limit: u64,
    response_bytes: usize,
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("{}: not valid JSON ({e})", path.display()))
}

fn optional_object(dir: &Path, file: &str) -> serde_json::Value {
    let path = dir.join(file);
    if !path.exists() {
        return serde_json::json!({});
    }
    let value = read_json(&path);
    assert!(
        value.is_object(),
        "{}: must be a JSON object",
        path.display()
    );
    value
}

fn string_list(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Every template with a recorded run, or just `TEMPLATE` when it is set.
fn recordings(root: &Path) -> Vec<Recording> {
    let only = std::env::var("TEMPLATE").ok().filter(|v| !v.is_empty());
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root)
        .expect("read module-templates")
        .flatten()
    {
        let dir = entry.path();
        let fixtures = dir.join("fixtures");
        if !fixtures.join("http.json").exists() {
            continue;
        }
        let slug = dir
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default()
            .to_string();
        if only.as_deref().is_some_and(|o| o != slug) {
            continue;
        }
        let template = talos_compilation::CatalogTemplate::load(&dir)
            .unwrap_or_else(|e| panic!("{slug}: {e}"));
        found.push(Recording {
            config: optional_object(&fixtures, "config.json"),
            input: optional_object(&fixtures, "input.json"),
            extra_hosts: string_list(&optional_object(&fixtures, "grants.json"), "allowed_hosts"),
            http: read_json(&fixtures.join("http.json")),
            slug,
            template,
        });
    }
    found.sort_by(|a, b| a.slug.cmp(&b.slug));
    if let Some(only) = only {
        assert!(
            !found.is_empty(),
            "TEMPLATE={only}: module-templates/{only}/fixtures/http.json not found"
        );
    }
    found
}

async fn measure(
    compiler: &talos_compilation::CompilationService,
    runtime: &TalosRuntime,
    recording: Recording,
) -> Measured {
    let Recording {
        slug,
        template,
        config,
        input,
        extra_hosts,
        http,
    } = recording;
    let manifest = template.manifest();

    // The limit the catalog row will carry. A template that ships a recorded
    // run must declare one — without it the row gets the shared default,
    // which nobody chose for this module — but an undeclared one is still
    // MEASURED (under the platform's ceiling) so the refusal can say what to
    // declare. That is the first run of a promotion.
    let declared = template
        .recommended_max_fuel()
        .unwrap_or_else(|reason| panic!("{slug}: {reason}"));
    let limit = declared.unwrap_or(talos_compilation::scaffold::FUEL_MAX);

    let fixtures = talos_worker_runtime::rehearsal::parse_http_fixtures(&http)
        .unwrap_or_else(|e| panic!("{slug}: fixtures/http.json: {e}"));
    let response_bytes: usize = fixtures.iter().map(|f| f.body.len()).sum();
    let replay = Arc::new(
        HttpReplay::for_rehearsal(fixtures)
            .unwrap_or_else(|e| panic!("{slug}: fixtures/http.json: {e}")),
    );

    let compiled = compiler
        .compile_catalog_template(uuid::Uuid::nil(), uuid::Uuid::new_v4(), &slug, &template)
        .await
        .unwrap_or_else(|e| panic!("{slug}: compile errored: {e:#}"));
    assert!(
        compiled.success,
        "{slug}: does not compile: {:#?}",
        compiled.errors
    );
    let wasm = compiled.wasm_bytes.expect("a successful compile has bytes");

    let mut allowed_hosts = string_list(manifest, "allowed_hosts");
    allowed_hosts.extend(extra_hosts);
    let fuel = Arc::new(Mutex::new(None));
    let output = runtime
        .execute_job_with_full_features(
            &wasm,
            allowed_hosts,
            string_list(manifest, "allowed_methods"),
            128,
            talos_worker_runtime::rehearsal::node_payload(&config, &input, None),
            None,
            None,
            std::collections::HashMap::new(),
            None,
            Duration::from_secs(60),
            // The recordings are handed out in order; a retry would run the
            // module again against whatever is left.
            RetryPolicy::controller_dispatched(),
            None,
            SecurityPolicy {
                http_replay: Some(replay.clone()),
                ..Default::default()
            },
            None,
            Some(limit),
            false,
            None,
            uuid::Uuid::nil(),
            LlmTier::Tier1,
            WriteCeiling::ReadOnly,
            None,
            Some(EgressScope::Public),
            None,
            None,
            0,
            None,
            Some(fuel.clone()),
        )
        .await;

    let measured = *fuel.lock().expect("fuel lock");
    let output = output.unwrap_or_else(|e| {
        panic!(
            "{slug}: the recorded run failed under its declared limit of {limit} fuel \
             (measured: {measured:?}): {e:#}"
        )
    });
    assert!(
        output.get("error").is_none(),
        "{slug}: the recorded run returned an error: {output}"
    );
    let (total, unused) = replay.unused();
    assert_eq!(
        unused, 0,
        "{slug}: {unused} of {total} recorded responses were never requested — the recording \
         no longer matches what the module does"
    );
    let consumed = measured
        .unwrap_or_else(|| panic!("{slug}: the run reported no fuel measurement"))
        .consumed;
    assert!(
        declared.is_some(),
        "{slug}: has a recorded run but declares no recommended_fuel in talos.json. This run \
         used {consumed} fuel over {response_bytes} bytes of recorded response; declare a \
         recommended_fuel whose limit keeps that under {:.0}% (docs/module-promotion.md).",
        HIGH_FUEL_UTILISATION * 100.0
    );
    Measured {
        slug,
        consumed,
        limit,
        response_bytes,
    }
}

fn utilisation(m: &Measured) -> f64 {
    // Display and one comparison against a two-decimal threshold.
    #[allow(clippy::cast_precision_loss)]
    {
        m.consumed as f64 / m.limit as f64
    }
}

fn report(measured: &[Measured]) -> String {
    let mut out = String::from(
        "| template | fuel used | declared limit | used | recorded response bytes |\n\
         |---|---:|---:|---:|---:|\n",
    );
    for m in measured {
        out.push_str(&format!(
            "| {} | {} | {} | {:.1}% | {} |\n",
            m.slug,
            m.consumed,
            m.limit,
            utilisation(m) * 100.0,
            m.response_bytes
        ));
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn every_recorded_run_fits_the_limit_its_manifest_declares() {
    if std::env::var("TALOS_TEST_CATALOG_FUEL").is_err() {
        eprintln!("skipping: set TALOS_TEST_CATALOG_FUEL=1 (make check-catalog-fuel)");
        return;
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let root = workspace.join("module-templates");
    std::env::set_var(
        "TALOS_SDK_MACROS_PATH",
        workspace
            .join("talos_sdk_macros")
            .canonicalize()
            .expect("talos_sdk_macros must exist"),
    );
    std::env::set_var("TALOS_COMPILATION_CONTAINER", "false");
    std::env::set_var("RUST_ENV", "development");

    let subjects = recordings(&root);
    assert!(
        !subjects.is_empty(),
        "no template carries fixtures/http.json — a green run over zero recordings proves nothing"
    );

    let workspaces = tempfile::tempdir().expect("workspace root");
    let (event_tx, _rx) = tokio::sync::broadcast::channel(64);
    let compiler =
        talos_compilation::CompilationService::new(PathBuf::from(workspaces.path()), event_tx);
    let runtime = TalosRuntime::with_resources(None, None, None).expect("worker runtime");

    let mut measured = Vec::new();
    for recording in subjects {
        measured.push(measure(&compiler, &runtime, recording).await);
    }

    let table = report(&measured);
    eprintln!("\n{table}");
    if let Some(summary) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(summary) {
            let _ = writeln!(file, "### Catalog templates: recorded-run fuel\n\n{table}");
        }
    }

    let over: Vec<String> = measured
        .iter()
        .filter(|m| utilisation(m) > HIGH_FUEL_UTILISATION)
        .map(|m| {
            format!(
                "{}: used {} of {} fuel ({:.1}%)",
                m.slug,
                m.consumed,
                m.limit,
                utilisation(m) * 100.0
            )
        })
        .collect();
    assert!(
        over.is_empty(),
        "recorded runs above {:.0}% of the declared limit — raise recommended_fuel in talos.json \
         (docs/module-promotion.md says how to size it):\n{}",
        HIGH_FUEL_UTILISATION * 100.0,
        over.join("\n")
    );
}
