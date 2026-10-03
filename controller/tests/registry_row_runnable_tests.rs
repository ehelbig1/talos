//! A catalog row a registry provides is a module that can run (2026-10-03).
//!
//! In registry mode a shared catalog row carries no compiled bytes: it names
//! a signed artifact (`oci_url`) that the worker pulls and verifies. Dispatch
//! was built for that. The surfaces that LIST and RESOLVE modules were not —
//! each asked "does this row hold bytes?" — so every module a registry
//! provided read as not compiled: `create_workflow_from_description` offered
//! none of them, and a workflow pattern naming one reported it missing.
//!
//! Each reader is driven here against a row written by the real registry
//! writer, beside a row that has NEITHER bytes nor a registry reference,
//! which must keep reading as unrunnable — that row is what the flag exists
//! to keep out.
//!
//! `common` harness, so the migrated-database job runs it.

mod common;

use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use talos_registry::reconcile::{upsert_catalog_template_by_slug, CatalogManifest, CatalogSource};
use talos_registry::ModuleRegistry;
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

fn manifest(display_name: &str) -> Value {
    json!({
        "name": "runnable-probe",
        "display_name": display_name,
        "category": "Network",
        "description": "Reads one thing.",
        "capability_world": "http-node",
        "allowed_hosts": ["api.example.test"],
        "allowed_methods": ["GET"],
    })
}

/// One row from the registry writer, one from the disk writer that nothing
/// has compiled. Returns `(registry_row, registry_name, bare_row, bare_name)`.
async fn seed(pool: &Pool<Postgres>) -> (Uuid, String, Uuid, String) {
    let tag = Uuid::new_v4().simple().to_string();
    let registry_name = format!("Runnable Registry {tag}");
    let bare_name = format!("Runnable Bare {tag}");
    let oci_url = format!("registry.example.test/talos-tools/runnable-{tag}:v1.0.0");

    let registry_row = upsert_catalog_template_by_slug(
        pool,
        CatalogManifest::parse(&manifest(&registry_name))
            .expect("accepted")
            .upsert(
                &format!("runnable-registry-{tag}"),
                CatalogSource::Registry { oci_url: &oci_url },
            ),
    )
    .await
    .expect("the registry row is written")
    .id;
    let bare_row = upsert_catalog_template_by_slug(
        pool,
        CatalogManifest::parse(&manifest(&bare_name))
            .expect("accepted")
            .upsert(
                &format!("runnable-bare-{tag}"),
                CatalogSource::Disk {
                    source_code: "pub fn run() {}",
                },
            ),
    )
    .await
    .expect("the disk row is written")
    .id;

    // The premise, read back rather than assumed: neither row holds bytes,
    // and only the registry row names an artifact.
    let shape: Vec<(Uuid, bool, bool)> = sqlx::query_as(
        "SELECT id, (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0), \
                COALESCE(oci_url, '') <> '' \
         FROM modules WHERE id = ANY($1) ORDER BY id",
    )
    .bind(vec![registry_row, bare_row])
    .fetch_all(pool)
    .await
    .expect("read the rows back");
    for (id, has_bytes, has_oci) in shape {
        assert!(!has_bytes, "{id}: a seeded row holds bytes");
        assert_eq!(has_oci, id == registry_row, "{id}: registry reference");
    }
    (registry_row, registry_name, bare_row, bare_name)
}

#[tokio::test]
async fn the_template_listing_counts_a_registry_row_as_runnable() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (registry_row, _, bare_row, _) = seed(&pool).await;
    let registry = ModuleRegistry::new(pool.clone(), None);

    // Both statements: the unfiltered listing and the per-category one.
    for category in [None, Some("Network")] {
        let listed = registry
            .list_template_metadata_for_user(Uuid::nil(), category)
            .await
            .expect("the listing reads");
        let flag = |id: Uuid| {
            listed
                .iter()
                .find(|t| t.id == id)
                .unwrap_or_else(|| panic!("{id} is not listed (category {category:?})"))
                .is_compiled
        };
        assert!(
            flag(registry_row),
            "a registry row reads as not compiled (category {category:?})"
        );
        assert!(
            !flag(bare_row),
            "a row with neither bytes nor a registry reference reads as compiled \
             (category {category:?})"
        );
    }
}

#[tokio::test]
async fn workflow_planning_sees_a_registry_row_and_not_a_bare_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (registry_row, registry_name, bare_row, bare_name) = seed(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());
    let user = Uuid::new_v4();

    let offered = repo
        .list_scaffolding_templates(user)
        .await
        .expect("the scaffolding listing reads");
    let flag = |id: Uuid| {
        offered
            .iter()
            .find(|t| t.id == id)
            .unwrap_or_else(|| panic!("{id} is not in the scaffolding listing"))
            .is_compiled
    };
    assert!(
        flag(registry_row),
        "planning would not offer a registry module"
    );
    assert!(
        !flag(bare_row),
        "planning would offer a module nothing can run"
    );

    assert_eq!(
        repo.find_compiled_template_by_name(&registry_name, user)
            .await
            .expect("name resolution reads"),
        Some(registry_row),
        "a pattern naming a registry module reports it missing"
    );
    assert_eq!(
        repo.find_compiled_template_by_name(&bare_name, user)
            .await
            .expect("name resolution reads"),
        None,
        "a pattern naming a module nothing can run resolves it"
    );
}

/// Dispatch loads a registry row with no bytes and its reference — the
/// worker pulls the artifact. An in-process run has nothing to execute and
/// must say so, instead of handing the runtime an empty binary.
#[tokio::test]
async fn a_registry_row_loads_for_dispatch_and_is_refused_in_process() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (registry_row, _, bare_row, _) = seed(&pool).await;
    let registry = ModuleRegistry::new(pool.clone(), None);
    let user = Uuid::new_v4();

    let module = registry
        .get_module(registry_row, user)
        .await
        .expect("a registry row loads for dispatch");
    assert!(module.wasm_bytes.is_empty());
    assert!(module.oci_url.as_deref().is_some_and(|u| !u.is_empty()));
    assert_eq!(
        module.in_process_bytes(),
        Err(talos_registry::RegistryArtifactOnly)
    );
    assert!(talos_registry::RegistryArtifactOnly
        .to_string()
        .contains("registry artifact"));

    // The far side: a row with neither is refused at the load itself.
    assert!(
        registry.get_module(bare_row, user).await.is_err(),
        "a row with neither bytes nor a registry reference loaded for dispatch"
    );
}

/// The three surfaces that run a STORED module in-process each ask
/// `in_process_bytes()` before they hand the runtime `module.wasm_bytes`.
/// A fourth surface added without it would hand a registry row's empty
/// binary to the runtime.
#[test]
fn every_in_process_run_of_a_stored_module_asks_for_its_bytes_first() {
    let stored_run = "&module.wasm_bytes,";
    let mut sites = 0;
    for (file, source) in [
        (
            "talos-mcp-handlers/src/sandbox.rs",
            include_str!("../../talos-mcp-handlers/src/sandbox.rs"),
        ),
        (
            "talos-replay-service/src/lib.rs",
            include_str!("../../talos-replay-service/src/lib.rs"),
        ),
        (
            "talos-api/src/schema/modules/mutations.rs",
            include_str!("../../talos-api/src/schema/modules/mutations.rs"),
        ),
        (
            "talos-mcp-handlers/src/advanced.rs",
            include_str!("../../talos-mcp-handlers/src/advanced.rs"),
        ),
    ] {
        let runs = source.matches(stored_run).count();
        sites += runs;
        if runs > 0 {
            let asked = source.find("in_process_bytes()").unwrap_or_else(|| {
                panic!("{file} runs a stored module in-process without in_process_bytes()")
            });
            let ran = source.find(stored_run).expect("counted above");
            assert!(
                asked < ran,
                "{file}: in_process_bytes() is asked after the module is run"
            );
        }
    }
    assert_eq!(
        sites, 3,
        "the population of in-process runs of a stored module changed; a new one must call \
         WasmModule::in_process_bytes() first, then update this count"
    );
}
