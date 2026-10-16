//! The deploy gate's walk over real `modules` rows (2026-10-16).
//!
//! `make up` runs `controller audit-module-worlds` from the candidate image
//! before starting it; this drives the PRODUCTION
//! `talos_module_world_audit::audit_installed_modules` against a real clone:
//! a row that links, a row a dispatch would refuse, a registry reference and
//! an evicted row (neither inspected), and a page boundary.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_module_repository::ModuleRepository;
use talos_module_world_audit::{audit_installed_modules, PAGE};
use uuid::Uuid;

const MEMORY_ONLY: &str = r#"(component
    (import "talos:core/agent-memory" (instance))
    (core module (memory 1)))"#;

async fn user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'audit')")
        .bind(id)
        .bind(format!("world-audit-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

async fn module(
    pool: &Pool<Postgres>,
    owner: Option<Uuid>,
    name: &str,
    world: &str,
    bytes: Option<&[u8]>,
    oci_url: Option<&str>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world, wasm_bytes, oci_url) \
         VALUES ($1, $2, $3, 'sandbox', $4, $5, $6)",
    )
    .bind(id)
    .bind(owner)
    .bind(name)
    .bind(world)
    .bind(bytes)
    .bind(oci_url)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

#[tokio::test]
async fn the_walk_names_the_refused_rows_and_counts_what_it_skipped() {
    let (pool, _db) = common::isolated_db_pool().await;
    let me = user(&pool).await;
    let bytes = wat::parse_str(MEMORY_ONLY).expect("component");

    let fits = module(&pool, Some(me), "fits", "agent-node", Some(&bytes), None).await;
    let refused = module(
        &pool,
        Some(me),
        "refused",
        "minimal-node",
        Some(&bytes),
        None,
    )
    .await;
    let unparseable = module(&pool, None, "odd", "llm-node", Some(&bytes), None).await;
    // Not inspected: a registry reference and an evicted row.
    module(
        &pool,
        Some(me),
        "registry",
        "http-node",
        None,
        Some("oci://r/x:1"),
    )
    .await;
    module(&pool, Some(me), "evicted", "minimal-node", None, None).await;

    let repo = ModuleRepository::new(pool.clone());
    let report = audit_installed_modules(&repo).await.expect("audit");

    assert_eq!(report.audited, 3, "{report:?}");
    assert_eq!(report.registry_unaudited, 1);
    assert!(!report.is_clean());
    let mut ids: Vec<Uuid> = report.findings.iter().map(|f| f.id).collect();
    ids.sort();
    let mut expected = vec![refused, unparseable];
    expected.sort();
    assert_eq!(ids, expected, "{report:?}");
    assert!(report.findings.iter().all(|f| f.id != fits));
    let r = report.findings.iter().find(|f| f.id == refused).unwrap();
    assert_eq!(r.declared_world, "minimal-node");
    assert_eq!(r.owner, Some(me));
    assert!(r.reason.contains("talos:core/agent-memory"), "{}", r.reason);
    let rendered = report.render();
    assert!(
        rendered.contains("REFUSED  refused (sandbox,"),
        "{rendered}"
    );
    assert!(
        rendered.contains("audited 3 module binaries: 2 would be refused"),
        "{rendered}"
    );
}

/// A fleet larger than one page is walked to the end, and a fleet of exactly
/// one page does not stop one row early.
#[tokio::test]
async fn the_walk_crosses_a_page_boundary() {
    let (pool, _db) = common::isolated_db_pool().await;
    let me = user(&pool).await;
    let bytes = wat::parse_str(MEMORY_ONLY).expect("component");
    let n = PAGE as usize + 3;
    for i in 0..n {
        let world = if i == n - 1 {
            "minimal-node"
        } else {
            "agent-node"
        };
        module(&pool, Some(me), &format!("m{i}"), world, Some(&bytes), None).await;
    }
    let repo = ModuleRepository::new(pool.clone());
    let report = audit_installed_modules(&repo).await.expect("audit");
    assert_eq!(report.audited, n);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].name, format!("m{}", n - 1));
}
