//! Installing a catalog module on a registry-mode deployment (2026-10-03).
//!
//! In registry mode the catalog is the shared rows the registry sync wrote,
//! each naming a signed artifact. `install_module_from_catalog` used to
//! ignore them: it read the template baked into the controller image and
//! COMPILED it, so the copy ran code the registry never published, and a
//! deployment with compiling off could not make a copy at all.
//!
//! Now the copy references the same artifact, with the installer's grants,
//! and nothing is compiled. These tests drive the real MCP dispatch over a
//! real `McpState` whose compile service is turned OFF — so an install that
//! succeeds here compiled nothing — against rows written by the real catalog
//! writer.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::sync::Arc;

use common::{create_test_user, setup_test_context};
use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres, Row};
use talos_module_repository::{InstalledArtifact, ModuleRepository};
use talos_registry::reconcile::{upsert_catalog_template_by_slug, CatalogManifest, CatalogSource};
use uuid::Uuid;

struct Shared {
    id: Uuid,
    slug: String,
    name: String,
    oci_url: String,
}

/// A shared catalog row as the registry sync writes one.
async fn registry_row(pool: &Pool<Postgres>) -> Shared {
    let tag = Uuid::new_v4().simple().to_string();
    let slug = format!("registry-install-{tag}");
    let name = format!("Registry Install {tag}");
    let oci_url = format!("registry.example.test/talos-tools/{slug}:v1.0.0");
    let manifest = json!({
        "name": slug,
        "display_name": name,
        "category": "Network",
        "description": "Reads one thing.",
        "capability_world": "http-node",
        "allowed_hosts": ["api.example.test"],
        "allowed_methods": ["GET"],
        "requires_secrets": ["example/api_key", "example/other_key"],
        "config_schema": {"type": "object", "properties": {"URL": {"type": "string"}}},
        "recommended_fuel": {"expected_items": 25, "bytes_per_item": 8000, "fuel_per_byte": 3, "safety_multiplier": 3.0}
    });
    let id = upsert_catalog_template_by_slug(
        pool,
        CatalogManifest::parse(&manifest)
            .expect("accepted")
            .upsert(&slug, CatalogSource::Registry { oci_url: &oci_url }),
    )
    .await
    .expect("the registry row is written")
    .id;
    Shared {
        id,
        slug,
        name,
        oci_url,
    }
}

/// The state every test here uses: production services, compiling OFF.
async fn state_without_a_compiler(pool: &Pool<Postgres>) -> controller::mcp::McpState {
    let mut state = mcp_state(pool.clone()).await;
    let (events, _rx) = tokio::sync::broadcast::channel(8);
    state.compiler = Arc::new(
        controller::compilation::CompilationService::new(
            std::path::PathBuf::from("/tmp/talos-compilations-test"),
            events,
        )
        .with_compilation_enabled(false),
    );
    state
}

async fn install(state: &controller::mcp::McpState, user: Uuid, args: Value) -> Value {
    let resp = controller::mcp::modules::dispatch(
        "install_module_from_catalog",
        Some(json!(1)),
        &args,
        state,
        agent(user),
    )
    .await
    .expect("install_module_from_catalog is dispatched");
    assert!(
        resp.error.is_none(),
        "the install was refused: {:?}",
        resp.error
    );
    text_json(&resp)
}

#[tokio::test]
async fn a_copy_references_the_registry_artifact_and_nothing_is_compiled() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "registry_install@example.com").await;
    let shared = registry_row(&pool).await;
    let state = state_without_a_compiler(&pool).await;

    // Narrow the secret grant to one of the two the template names, and ask
    // for one it does not name.
    let body = install(
        &state,
        user,
        json!({
            "name": shared.slug,
            "allowed_secrets": ["example/api_key", "somewhere/else"],
        }),
    )
    .await;
    assert_eq!(body["source"], "registry", "{body}");
    assert_eq!(body["wasm_sha256"], Value::Null, "{body}");
    assert_eq!(
        body["allowed_secrets"],
        json!(["example/api_key"]),
        "{body}"
    );
    assert_eq!(
        body["secrets_not_granted"],
        json!(["somewhere/else"]),
        "{body}"
    );
    let copy_id: Uuid = body["module_id"].as_str().unwrap().parse().unwrap();
    assert_ne!(copy_id, shared.id, "the install returned the shared row");

    let row = sqlx::query(
        "SELECT user_id, name, kind, capability_world, oci_url, catalog_slug, max_fuel, \
                wasm_bytes IS NULL AS no_bytes, COALESCE(source_code, '') AS source_code, \
                allowed_hosts, allowed_methods, allowed_secrets, config_schema \
         FROM modules WHERE id = $1",
    )
    .bind(copy_id)
    .fetch_one(&pool)
    .await
    .expect("the copy exists");
    assert_eq!(row.get::<Option<Uuid>, _>("user_id"), Some(user));
    assert_eq!(row.get::<String, _>("name"), shared.name);
    assert_eq!(row.get::<String, _>("capability_world"), "http-node");
    assert_eq!(
        row.get::<Option<String>, _>("oci_url").as_deref(),
        Some(shared.oci_url.as_str()),
        "the copy does not name the artifact its catalog row names"
    );
    assert!(
        row.get::<bool, _>("no_bytes"),
        "a reference copy holds bytes"
    );
    assert_eq!(row.get::<String, _>("source_code"), "");
    assert_eq!(
        row.get::<Option<String>, _>("catalog_slug").as_deref(),
        Some(shared.slug.as_str())
    );
    assert_eq!(
        row.get::<Vec<String>, _>("allowed_hosts"),
        vec!["api.example.test"]
    );
    assert_eq!(row.get::<Vec<String>, _>("allowed_methods"), vec!["GET"]);
    assert_eq!(
        row.get::<Vec<String>, _>("allowed_secrets"),
        vec!["example/api_key"]
    );
    assert_eq!(
        row.get::<Value, _>("config_schema")["properties"]["URL"]["type"],
        "string"
    );
    // The limit the catalog writer resolved from the published manifest.
    let shared_fuel: i64 = sqlx::query_scalar("SELECT max_fuel FROM modules WHERE id = $1")
        .bind(shared.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("max_fuel"), shared_fuel);
    assert_ne!(shared_fuel, 2_000_000, "the fixture's limit is the default");

    // Recorded, naming the artifact.
    let (event_type, details): (String, Value) = sqlx::query_as(
        "SELECT event_type, details FROM admin_event_log \
         WHERE resource_type = 'module' AND resource_id = $1",
    )
    .bind(copy_id)
    .fetch_one(&pool)
    .await
    .expect("the install is recorded");
    assert_eq!(event_type, "module_installed_from_catalog");
    assert_eq!(details["oci_url"], json!(shared.oci_url));

    // It loads for dispatch as a reference: the worker pulls the artifact.
    let loaded = state
        .registry
        .get_module(copy_id, user)
        .await
        .expect("the copy loads for dispatch");
    assert!(loaded.wasm_bytes.is_empty());
    assert_eq!(loaded.oci_url.as_deref(), Some(shared.oci_url.as_str()));
}

#[tokio::test]
async fn the_display_name_finds_the_registry_entry_and_an_unknown_key_does_not() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "registry_install_name@example.com").await;
    let shared = registry_row(&pool).await;
    let state = state_without_a_compiler(&pool).await;

    let body = install(&state, user, json!({ "name": shared.name.to_uppercase() })).await;
    assert_eq!(body["source"], "registry", "{body}");

    // No registry row: the image's template directory is read, as before.
    // There is none in the test environment, so this is "not in the catalog"
    // — and not a compile attempt.
    let resp = controller::mcp::modules::dispatch(
        "install_module_from_catalog",
        Some(json!(1)),
        &json!({ "name": "no-such-registry-module" }),
        &state,
        agent(user),
    )
    .await
    .expect("dispatched");
    assert!(
        error_message(&resp).contains("not found in catalog"),
        "{}",
        error_message(&resp)
    );
}

#[tokio::test]
async fn a_reference_copy_is_not_hot_updated_or_run_in_process_and_reads_as_present() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "registry_install_ops@example.com").await;
    let shared = registry_row(&pool).await;
    let state = state_without_a_compiler(&pool).await;
    let body = install(
        &state,
        user,
        json!({ "name": shared.slug, "pin_module": true }),
    )
    .await;
    assert_eq!(body["pinned"], true, "{body}");
    let copy_id = body["module_id"].as_str().unwrap().to_string();

    // Hot update: there is no code on the row to update, and bytes written
    // onto it would change nothing dispatch runs.
    let resp = controller::mcp::sandbox::dispatch(
        "hot_update_module",
        Some(json!(1)),
        &json!({
            "module_id": copy_id,
            "rust_code": "pub fn run(i: String) -> Result<String, String> { Ok(i) }",
        }),
        &state,
        agent(user),
    )
    .await
    .expect("hot_update_module is dispatched");
    assert_eq!(
        error_message(&resp),
        talos_hot_update_service::REGISTRY_REFERENCE_NOT_EDITABLE
    );
    let still: (Option<String>, bool) =
        sqlx::query_as("SELECT oci_url, wasm_bytes IS NULL FROM modules WHERE id = $1::uuid")
            .bind(&copy_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(still.0.as_deref(), Some(shared.oci_url.as_str()));
    assert!(still.1, "a refused hot update wrote bytes");

    // An in-process run has nothing to execute.
    let resp = controller::mcp::sandbox::dispatch(
        "test_module",
        Some(json!(1)),
        &json!({ "module_id": copy_id, "input": {} }),
        &state,
        agent(user),
    )
    .await
    .expect("test_module is dispatched");
    assert_eq!(
        error_message(&resp),
        talos_registry::REGISTRY_ARTIFACT_NOT_RUNNABLE_IN_PROCESS
    );

    // restore_pinned_modules must not try to rebuild it.
    let pinned = ModuleRepository::new(pool.clone())
        .list_user_pinned_modules(user)
        .await
        .expect("the pin list reads");
    let pin = pinned
        .iter()
        .find(|p| p.module_name == shared.name)
        .expect("the copy is pinned");
    assert!(pin.has_wasm, "a reference copy reads as needing a rebuild");
}

/// One writer stores both kinds of copy, and a reinstall that changes which
/// kind a copy is leaves no trace of the other: never bytes beside a
/// reference.
#[tokio::test]
async fn a_reinstall_that_changes_the_kind_of_copy_replaces_the_other_kind() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "registry_install_flip@example.com").await;
    let repo = ModuleRepository::new(pool.clone());
    let hosts = vec!["api.example.test".to_string()];
    let methods = vec!["GET".to_string()];

    let shape = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (bool, Option<String>, String, Option<String>)>(
                "SELECT COALESCE(octet_length(wasm_bytes), 0) > 0, oci_url, \
                        COALESCE(source_code, ''), content_hash \
                 FROM modules WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let write = |artifact: InstalledArtifact<'static>| {
        let repo = &repo;
        let hosts = &hosts;
        let methods = &methods;
        async move {
            repo.install_catalog_copy(
                Some(user),
                "Flip Probe",
                "http",
                artifact,
                2_000_000,
                hosts,
                methods,
                &[],
                &[],
                &json!({}),
                Some("flip-probe"),
                false,
            )
            .await
            .expect("the copy is written")
        }
    };

    let compiled = InstalledArtifact::Compiled {
        wasm_bytes: b"\0asm-not-really",
        content_hash: "abc123",
        source_code: "pub fn run() {}",
        dependencies: None,
    };
    let reference = InstalledArtifact::Registry {
        oci_url: "registry.example.test/talos-tools/flip-probe:v1.0.0",
    };

    let first = write(compiled).await;
    assert_eq!(
        shape(first.module_id).await,
        (
            true,
            None,
            "pub fn run() {}".to_string(),
            Some("abc123".to_string())
        )
    );

    let second = write(reference).await;
    assert_eq!(
        second.module_id, first.module_id,
        "a reinstall keeps the id"
    );
    assert!(second.bytes_changed, "the artifact changed");
    assert_eq!(
        shape(first.module_id).await,
        (
            false,
            Some("registry.example.test/talos-tools/flip-probe:v1.0.0".to_string()),
            String::new(),
            Some("oci:registry.example.test/talos-tools/flip-probe:v1.0.0".to_string())
        )
    );
    // The same reference again is not a change.
    assert!(!write(reference).await.bytes_changed);

    let third = write(compiled).await;
    assert_eq!(third.module_id, first.module_id);
    assert_eq!(
        shape(first.module_id).await,
        (
            true,
            None,
            "pub fn run() {}".to_string(),
            Some("abc123".to_string())
        ),
        "a compiled reinstall left the registry reference on the row"
    );

    // A reference with nothing in it is refused, not stored.
    assert!(repo
        .install_catalog_copy(
            Some(user),
            "Flip Probe",
            "http",
            InstalledArtifact::Registry { oci_url: "  " },
            2_000_000,
            &hosts,
            &methods,
            &[],
            &[],
            &json!({}),
            Some("flip-probe"),
            false,
        )
        .await
        .is_err());
}

/// What a registry-mode deployment lists: its registry rows, and only those.
#[tokio::test]
async fn the_registry_catalog_is_the_rows_that_name_an_artifact() {
    let (pool, _db) = common::isolated_db_pool().await;
    let shared = registry_row(&pool).await;
    let bare_slug = format!("registry-install-bare-{}", Uuid::new_v4().simple());
    upsert_catalog_template_by_slug(
        &pool,
        CatalogManifest::parse(&json!({
            "name": bare_slug,
            "display_name": format!("Bare {bare_slug}"),
            "capability_world": "minimal-node",
        }))
        .expect("accepted")
        .upsert(
            &bare_slug,
            CatalogSource::Disk {
                source_code: "pub fn run() {}",
            },
        ),
    )
    .await
    .expect("the disk row is written");

    let repo = ModuleRepository::new(pool.clone());
    let listed = repo
        .list_shared_registry_entries()
        .await
        .expect("the registry catalog reads");
    assert!(listed.iter().any(|e| e.id == shared.id));
    assert!(
        listed
            .iter()
            .all(|e| e.catalog_slug.as_deref() != Some(bare_slug.as_str())),
        "a row with no registry reference is in the registry catalog"
    );
    let entry = listed.iter().find(|e| e.id == shared.id).unwrap();
    assert_eq!(entry.oci_url, shared.oci_url);
    assert_eq!(entry.allowed_methods, vec!["GET"]);
    assert_eq!(
        entry.allowed_secrets,
        vec!["example/api_key", "example/other_key"]
    );

    assert!(repo
        .find_shared_registry_entry(&bare_slug)
        .await
        .expect("reads")
        .is_none());
    assert_eq!(
        repo.find_shared_registry_entry(&shared.slug)
            .await
            .expect("reads")
            .map(|e| e.id),
        Some(shared.id)
    );
}

/// The catalog is the SHARED rows. A user's own reference copy also names a
/// registry artifact and carries that user's grants; it must never be read
/// as a catalog entry, or another user's install would copy those grants.
#[tokio::test]
async fn one_users_reference_copy_is_never_a_catalog_entry() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let owner = create_test_user(&ctx.auth_service, "registry_install_owner@example.com").await;
    let other = create_test_user(&ctx.auth_service, "registry_install_other@example.com").await;
    let shared = registry_row(&pool).await;
    let state = state_without_a_compiler(&pool).await;

    let private_name = format!("Private Copy {}", Uuid::new_v4().simple());
    let body = install(
        &state,
        owner,
        json!({ "name": shared.slug, "display_name": private_name }),
    )
    .await;
    let copy_id: Uuid = body["module_id"].as_str().unwrap().parse().unwrap();

    let repo = ModuleRepository::new(pool.clone());
    assert!(
        repo.find_shared_registry_entry(&private_name)
            .await
            .expect("reads")
            .is_none(),
        "a user's own copy was found as a catalog entry"
    );
    assert!(repo
        .list_shared_registry_entries()
        .await
        .expect("reads")
        .iter()
        .all(|e| e.id != copy_id));

    // And through the tool: the other user cannot install "from" it.
    let resp = controller::mcp::modules::dispatch(
        "install_module_from_catalog",
        Some(json!(1)),
        &json!({ "name": private_name }),
        &state,
        agent(other),
    )
    .await
    .expect("dispatched");
    assert!(
        error_message(&resp).contains("not found in catalog"),
        "{}",
        error_message(&resp)
    );
}

/// A copy keeps the registry reference it was installed with. While its
/// catalog row names the same one the copy is current; when the catalog moves
/// to a new tag the copy is behind until it is reinstalled — and the report
/// says which, instead of "unknown".
#[tokio::test]
async fn a_reference_copy_is_current_until_the_catalog_moves_to_a_new_artifact() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "registry_install_drift@example.com").await;
    let shared = registry_row(&pool).await;
    let state = state_without_a_compiler(&pool).await;
    let repo = ModuleRepository::new(pool.clone());
    install(&state, user, json!({ "name": shared.slug })).await;

    async fn standing(repo: &ModuleRepository, user: Uuid) -> (&'static str, Vec<&'static str>) {
        let rows = repo
            .list_catalog_copy_drift(user)
            .await
            .expect("the drift report reads");
        assert_eq!(rows.len(), 1, "one installed copy");
        (
            talos_module_repository::CatalogCopyState::of(&rows[0]).as_str(),
            rows[0].differs_in(),
        )
    }
    assert_eq!(standing(&repo, user).await, ("current", vec![]));

    // The registry publishes a new version: the sync rewrites the shared row
    // with the new tag. Same slug, same manifest.
    let moved = format!("registry.example.test/talos-tools/{}:v1.1.0", shared.slug);
    let manifest = json!({
        "name": shared.slug,
        "display_name": shared.name,
        "category": "Network",
        "description": "Reads one thing.",
        "capability_world": "http-node",
        "allowed_hosts": ["api.example.test"],
        "allowed_methods": ["GET"],
        "requires_secrets": ["example/api_key", "example/other_key"],
        "config_schema": {"type": "object", "properties": {"URL": {"type": "string"}}},
        "recommended_fuel": {"expected_items": 25, "bytes_per_item": 8000, "fuel_per_byte": 3, "safety_multiplier": 3.0}
    });
    let rewritten = upsert_catalog_template_by_slug(
        &pool,
        CatalogManifest::parse(&manifest)
            .expect("accepted")
            .upsert(&shared.slug, CatalogSource::Registry { oci_url: &moved }),
    )
    .await
    .expect("the shared row is rewritten")
    .id;
    assert_eq!(rewritten, shared.id, "the sync rewrote a different row");
    assert_eq!(standing(&repo, user).await, ("behind", vec!["artifact"]));

    // A reinstall takes the catalog's reference.
    let body = install(&state, user, json!({ "name": shared.slug })).await;
    assert_eq!(body["bytes_changed"], true, "{body}");
    assert_eq!(standing(&repo, user).await, ("current", vec![]));
}
