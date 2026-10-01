//! A catalog install is recorded in `admin_event_log` in the SAME transaction
//! as the write, and the record names what the install replaced.
//!
//! `install_module_from_catalog` replaces a module's code and can replace its
//! capability world and all three grant lists. Until 2026-10-01 it wrote no
//! record: the one module-grant writer the 2026-09-19 privilege-audit package
//! did not reach. These tests drive the repository writer the MCP handler
//! calls (its only caller) and read `admin_event_log` back.

mod common;

use serde_json::{json, Value};
use sqlx::{Pool, Postgres, Row};
use talos_module_repository::ModuleRepository;
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'install audit')",
    )
    .bind(id)
    .bind(format!("install-audit-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

struct Grants<'a> {
    world: &'a str,
    hosts: &'a [&'a str],
    methods: &'a [&'a str],
    secrets: &'a [&'a str],
}

async fn install(
    repo: &ModuleRepository,
    user: Uuid,
    wasm: &[u8],
    hash: &str,
    g: &Grants<'_>,
) -> anyhow::Result<Uuid> {
    let v = |xs: &[&str]| xs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    Ok(repo
        .install_catalog_module_to_modules(
            Some(user),
            "Gmail: List Messages",
            g.world,
            wasm,
            hash,
            "fn run() {}",
            2_000_000,
            &v(g.hosts),
            &v(g.methods),
            &v(g.secrets),
            &[],
            &json!({}),
            Some("gmail-list"),
            false,
        )
        .await?
        .module_id)
}

async fn events(pool: &Pool<Postgres>) -> Vec<(Option<Uuid>, String, Option<Uuid>, String, Value)> {
    sqlx::query(
        "SELECT user_id, event_type, resource_id, summary, details FROM admin_event_log \
         WHERE resource_type = 'module' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("events")
    .into_iter()
    .map(|r| {
        (
            r.try_get("user_id").unwrap(),
            r.try_get("event_type").unwrap(),
            r.try_get("resource_id").unwrap(),
            r.try_get("summary").unwrap(),
            r.try_get::<Option<Value>, _>("details")
                .unwrap()
                .unwrap_or(Value::Null),
        )
    })
    .collect()
}

async fn stored(pool: &Pool<Postgres>, id: Uuid) -> (String, Vec<String>, String) {
    let r = sqlx::query(
        "SELECT capability_world, allowed_secrets, content_hash FROM modules WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("module row");
    (
        r.try_get("capability_world").unwrap(),
        r.try_get("allowed_secrets").unwrap(),
        r.try_get("content_hash").unwrap(),
    )
}

const NARROW: Grants<'static> = Grants {
    world: "http",
    hosts: &["gmail.googleapis.com"],
    methods: &["GET"],
    secrets: &["oauth/gmail/primary/access_token"],
};
const WIDE: Grants<'static> = Grants {
    world: "http",
    hosts: &["gmail.googleapis.com"],
    methods: &["GET"],
    secrets: &["oauth/gmail/*"],
};

#[tokio::test]
async fn a_first_install_and_a_reinstall_each_record_what_they_wrote_and_replaced() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = ModuleRepository::new(pool.clone());

    let id = install(&repo, user, b"wasm-v1", "hash-v1", &NARROW)
        .await
        .unwrap();
    let ev = events(&pool).await;
    assert_eq!(ev.len(), 1, "{ev:?}");
    let (by, kind, resource, summary, details) = &ev[0];
    assert_eq!(kind, "module_installed_from_catalog");
    assert_eq!(*by, Some(user));
    assert_eq!(*resource, Some(id));
    assert!(summary.contains("Gmail: List Messages") && summary.contains("gmail-list"));
    assert_eq!(details["capability_world"], "http-node");
    assert_eq!(details["allowed_secrets"], json!(NARROW.secrets));
    assert_eq!(details["content_hash"], "hash-v1");
    assert!(
        details.get("previous_allowed_secrets").is_none(),
        "a first install replaced nothing: {details}"
    );

    // A reinstall that widens the secret grant and changes the code lands on
    // the same row and records both, with the values it replaced.
    let again = install(&repo, user, b"wasm-v2", "hash-v2", &WIDE)
        .await
        .unwrap();
    assert_eq!(again, id);
    let ev = events(&pool).await;
    assert_eq!(ev.len(), 2, "{ev:?}");
    let (_, kind, resource, summary, details) = &ev[1];
    assert_eq!(kind, "module_reinstalled_from_catalog");
    assert_eq!(*resource, Some(id));
    assert!(
        summary.contains("code changed") && summary.contains("grants changed"),
        "{summary}"
    );
    assert_eq!(details["allowed_secrets"], json!(WIDE.secrets));
    assert_eq!(details["previous_allowed_secrets"], json!(NARROW.secrets));
    assert_eq!(details["previous_content_hash"], "hash-v1");
    assert_eq!(details["code_changed"], true);
    assert_eq!(details["grants_changed"], true);

    // CONTROL: an identical reinstall is still recorded (an install happened)
    // and says nothing changed.
    install(&repo, user, b"wasm-v2", "hash-v2", &WIDE)
        .await
        .unwrap();
    let ev = events(&pool).await;
    assert_eq!(ev.len(), 3);
    assert_eq!(ev[2].4["code_changed"], false);
    assert_eq!(ev[2].4["grants_changed"], false);
    assert!(ev[2].3.contains("code unchanged") && ev[2].3.contains("grants unchanged"));
}

/// With the audit table unavailable, the install does not happen: the row
/// keeps its code and its grants.
#[tokio::test]
async fn an_install_that_cannot_be_recorded_changes_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = ModuleRepository::new(pool.clone());
    let id = install(&repo, user, b"wasm-v1", "hash-v1", &NARROW)
        .await
        .unwrap();

    sqlx::query("ALTER TABLE admin_event_log RENAME TO admin_event_log_moved")
        .execute(&pool)
        .await
        .unwrap();

    let refused = install(&repo, user, b"wasm-v2", "hash-v2", &WIDE).await;
    assert!(refused.is_err(), "an unrecordable install must fail");
    let (world, secrets, hash) = stored(&pool, id).await;
    assert_eq!(world, "http-node");
    assert_eq!(secrets, NARROW.secrets);
    assert_eq!(hash, "hash-v1");

    // A first install that cannot be recorded leaves no row at all.
    let other = seed_user(&pool).await;
    assert!(install(&repo, other, b"wasm-v1", "hash-v1", &NARROW)
        .await
        .is_err());
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM modules WHERE user_id = $1")
        .bind(other)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
