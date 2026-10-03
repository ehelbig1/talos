//! One parser and one writer for shared catalog rows (2026-10-03).
//!
//! Two code paths write the shared row of a catalog template: the disk seed
//! and the registry sync. Each used to parse the manifest and write the row
//! itself, and they had drifted — a row from the registry carried no verbs,
//! no capability world, no dependencies and no fuel limit, so no HTTP
//! template synced from a registry could make a request.
//!
//! Driven through the real parser and the real row writer against a real
//! clone. `common` harness, so the migrated-database job runs it.

mod common;

use serde_json::{json, Value};
use sqlx::{Pool, Postgres, Row};
use talos_registry::reconcile::{upsert_catalog_template_by_slug, CatalogManifest, CatalogSource};
use uuid::Uuid;

/// A manifest that sets every field a shared row stores.
fn manifest(display_name: &str) -> Value {
    json!({
        "name": "one-writer",
        "display_name": display_name,
        "category": "Network",
        "description": "Reads one thing.",
        "capability_world": "http-node",
        "allowed_hosts": ["api.example.test"],
        "allowed_methods": ["GET", "POST"],
        "requires_secrets": ["example/api_key"],
        "requires_approval_for": ["send"],
        "config_schema": {"type": "object", "properties": {"URL": {"type": "string"}}},
        "dependencies": {"chrono": "0.4"},
        "recommended_fuel": {"expected_items": 25, "bytes_per_item": 8000, "fuel_per_byte": 3, "safety_multiplier": 3.0}
    })
}

async fn write(
    pool: &Pool<Postgres>,
    manifest: &Value,
    slug: &str,
    source: CatalogSource<'_>,
) -> (Uuid, bool) {
    let parsed = CatalogManifest::parse(manifest).expect("the manifest is accepted");
    let registered = upsert_catalog_template_by_slug(pool, parsed.upsert(slug, source))
        .await
        .expect("the row is written");
    (registered.id, registered.needs_recompile)
}

/// Every column of the row that the manifest decides, as text.
async fn manifest_columns(pool: &Pool<Postgres>, id: Uuid) -> Vec<(String, Option<String>)> {
    const COLUMNS: [&str; 10] = [
        "category",
        "description",
        "config_schema",
        "allowed_hosts",
        "allowed_methods",
        "allowed_secrets",
        "requires_approval_for",
        "capability_world",
        "dependencies",
        "max_fuel",
    ];
    let mut out = Vec::new();
    for column in COLUMNS {
        // A fixed list of column names, not caller input.
        let value: Option<String> =
            sqlx::query_scalar(&format!("SELECT {column}::text FROM modules WHERE id = $1"))
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("{column}: {e}"));
        out.push((column.to_string(), value));
    }
    out
}

async fn source_columns(pool: &Pool<Postgres>, id: Uuid) -> (String, Option<String>, String, bool) {
    let row = sqlx::query(
        "SELECT source_code, oci_url, kind, user_id IS NULL AS shared FROM modules WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("the row");
    (
        row.get::<Option<String>, _>("source_code")
            .unwrap_or_default(),
        row.get("oci_url"),
        row.get("kind"),
        row.get("shared"),
    )
}

/// The same manifest through either writer stores the same thing in every
/// column the manifest decides. This is the property the two hand-written
/// writers did not have.
#[tokio::test]
async fn both_sources_store_the_same_manifest_fields() {
    let (pool, _db) = common::isolated_db_pool().await;
    let tag = Uuid::new_v4().simple().to_string();
    let disk_slug = format!("one-writer-disk-{tag}");
    let registry_slug = format!("one-writer-registry-{tag}");

    let (disk, disk_recompile) = write(
        &pool,
        &manifest(&format!("One Writer Disk {tag}")),
        &disk_slug,
        CatalogSource::Disk {
            source_code: "pub fn run() {}",
        },
    )
    .await;
    let url = format!(
        "oci://registry.example.test/talos-tools/{registry_slug}:v1@sha256:{}",
        "a".repeat(64)
    );
    let (registry, registry_recompile) = write(
        &pool,
        &manifest(&format!("One Writer Registry {tag}")),
        &registry_slug,
        CatalogSource::Registry { oci_url: &url },
    )
    .await;

    let from_disk = manifest_columns(&pool, disk).await;
    assert_eq!(from_disk, manifest_columns(&pool, registry).await);
    // …and they are the manifest's values, not two matching defaults.
    let value = |column: &str| {
        from_disk
            .iter()
            .find(|(c, _)| c == column)
            .and_then(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(value("capability_world"), "http-node");
    assert_eq!(value("allowed_methods"), "{GET,POST}");
    assert_eq!(value("allowed_hosts"), "{api.example.test}");
    assert_eq!(value("allowed_secrets"), "{example/api_key}");
    let recommended = talos_compilation::recommended_max_fuel(&manifest("x"))
        .expect("readable")
        .expect("declared");
    assert_eq!(value("max_fuel"), recommended.to_string());
    assert_ne!(recommended, 2_000_000, "not the column default");
    assert!(value("dependencies").contains("chrono"));

    // What differs is where the code comes from, and only that.
    assert_eq!(
        source_columns(&pool, disk).await,
        (
            "pub fn run() {}".to_string(),
            None,
            "catalog".to_string(),
            true
        )
    );
    assert_eq!(
        source_columns(&pool, registry).await,
        (String::new(), Some(url), "catalog".to_string(), true)
    );
    assert!(
        disk_recompile,
        "a new disk row has no bytes yet and is compiled here"
    );
    assert!(
        !registry_recompile,
        "a registry row's bytes are the worker's to pull"
    );
}

/// A deployment that changes mode: the row says which source wrote it last,
/// because dispatch prefers the registry URL whenever one is set.
#[tokio::test]
async fn a_row_follows_the_source_that_wrote_it_last() {
    let (pool, _db) = common::isolated_db_pool().await;
    let tag = Uuid::new_v4().simple().to_string();
    let slug = format!("one-writer-switch-{tag}");
    let m = manifest(&format!("One Writer Switch {tag}"));
    let url = format!(
        "oci://registry.example.test/talos-tools/{slug}:v1@sha256:{}",
        "b".repeat(64)
    );

    let (id, _) = write(
        &pool,
        &m,
        &slug,
        CatalogSource::Disk {
            source_code: "pub fn run() {}",
        },
    )
    .await;
    let (again, recompile) =
        write(&pool, &m, &slug, CatalogSource::Registry { oci_url: &url }).await;
    assert_eq!(
        again, id,
        "the slug names one row whichever source writes it"
    );
    assert!(!recompile);
    let (source, oci, _, _) = source_columns(&pool, id).await;
    assert_eq!(oci.as_deref(), Some(url.as_str()));
    assert_eq!(
        source, "pub fn run() {}",
        "the stored source is left as it was"
    );

    // A re-sync at a new digest moves the URL.
    let newer = url.replace(&"b".repeat(64), &"c".repeat(64));
    write(
        &pool,
        &m,
        &slug,
        CatalogSource::Registry { oci_url: &newer },
    )
    .await;
    assert_eq!(
        source_columns(&pool, id).await.1.as_deref(),
        Some(newer.as_str())
    );

    // Back to the disk seed: no registry URL left to dispatch to.
    write(
        &pool,
        &m,
        &slug,
        CatalogSource::Disk {
            source_code: "pub fn run() { /* v2 */ }",
        },
    )
    .await;
    let (source, oci, _, _) = source_columns(&pool, id).await;
    assert_eq!(oci, None);
    assert_eq!(source, "pub fn run() { /* v2 */ }");
}

/// A manifest whose display name changed updates the row its slug names; it
/// does not mint a second one. The registry sync used to key on the name.
#[tokio::test]
async fn a_renamed_registry_template_keeps_its_row() {
    let (pool, _db) = common::isolated_db_pool().await;
    let tag = Uuid::new_v4().simple().to_string();
    let slug = format!("one-writer-rename-{tag}");
    let url = format!(
        "oci://registry.example.test/talos-tools/{slug}:v1@sha256:{}",
        "d".repeat(64)
    );
    let source = CatalogSource::Registry { oci_url: &url };

    let (id, _) = write(&pool, &manifest(&format!("Before {tag}")), &slug, source).await;
    let (renamed, _) = write(&pool, &manifest(&format!("After {tag}")), &slug, source).await;
    assert_eq!(renamed, id);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM modules WHERE catalog_slug = $1")
        .bind(&slug)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1);
    let name: String = sqlx::query_scalar("SELECT name FROM modules WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("name");
    assert_eq!(name, format!("After {tag}"));
}
