//! What a module's owner adds to its grants is recorded, and a catalog
//! reinstall keeps it (2026-10-04).
//!
//! A reinstall keeps a copy's grants only within the new template's grant.
//! For a template that installs with no host and no secret — the owner is
//! meant to add them — that wiped the copy back to reaching nothing on every
//! reinstall. The permission writer now records the entries the owner adds,
//! in the same statement as the grant, and the install writer stores the
//! record beside the lists it describes.
//!
//! Driven against a real database through the two repository writers the MCP
//! handlers call. The rule deciding WHICH entries a reinstall keeps is pure
//! and unit-tested where it lives (`talos-mcp-handlers`, `grants_for_install`);
//! here the matcher is a plain "not already held".
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

mod common;

use serde_json::json;
use sqlx::{Pool, Postgres};
use talos_module_repository::{ModuleRepository, OwnerAddedGrants};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(id)
    .bind(format!("{id}@owner-added.test"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

fn v(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

/// Beyond the inherited part: not already held by it.
fn beyond(inherited: &[String], new: &[String]) -> Vec<String> {
    new.iter()
        .filter(|e| !inherited.contains(e))
        .cloned()
        .collect()
}

const NAME: &str = "Notify: Example";

/// Install (or reinstall) the copy with these grants and this record.
async fn install(
    repo: &ModuleRepository,
    user: Uuid,
    hosts: &[&str],
    secrets: &[&str],
    owner_added: &OwnerAddedGrants,
) -> anyhow::Result<Uuid> {
    Ok(repo
        .install_catalog_copy(
            Some(user),
            NAME,
            "http",
            talos_module_repository::InstalledArtifact::Compiled {
                wasm_bytes: b"\0asm-made-up",
                content_hash: "made-up-hash",
                source_code: "fn run() {}",
                dependencies: None,
            },
            1_000_000,
            &v(hosts),
            &v(&["POST"]),
            &v(secrets),
            &[],
            &json!({}),
            Some("notify-example"),
            false,
            owner_added,
        )
        .await?
        .module_id)
}

#[tokio::test]
async fn what_the_owner_adds_is_recorded_with_the_grant_and_survives_a_reinstall() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ModuleRepository::new(pool.clone());
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;

    // A template that grants nothing: the copy starts able to reach nothing.
    let module = install(&repo, owner, &[], &[], &OwnerAddedGrants::default())
        .await
        .expect("first install");
    let fresh = repo
        .get_user_module_grants(owner, NAME)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fresh.owner_added, OwnerAddedGrants::default());

    // The owner grants one host and one secret path.
    let hosts = repo
        .update_module_allowed_hosts(module, owner, &v(&["home.example.test"]), &beyond)
        .await
        .unwrap()
        .expect("the owner's module");
    assert_eq!(hosts.owner_added, v(&["home.example.test"]));
    let secrets = repo
        .update_module_allowed_secrets(module, owner, &v(&["svc/token"]), &beyond)
        .await
        .unwrap()
        .expect("the owner's module");
    assert_eq!(secrets.owner_added, v(&["svc/token"]));

    let stored = repo
        .get_user_module_grants(owner, NAME)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.hosts, v(&["home.example.test"]));
    assert_eq!(stored.owner_added.hosts, v(&["home.example.test"]));
    assert_eq!(stored.owner_added.secrets, v(&["svc/token"]));
    assert!(stored.owner_added.methods.is_empty(), "POST was inherited");

    // The change is recorded with what was marked as the owner's.
    let details: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM admin_event_log \
         WHERE event_type = 'module_allowed_hosts_updated' AND resource_id = $1",
    )
    .bind(module)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(details["owner_added"], json!(["home.example.test"]));

    // Someone else cannot touch the grant or its record.
    let other = repo
        .update_module_allowed_hosts(module, stranger, &v(&["evil.example.test"]), &beyond)
        .await
        .unwrap();
    assert!(other.is_none());
    assert_eq!(
        repo.get_user_module_grants(owner, NAME)
            .await
            .unwrap()
            .unwrap(),
        stored
    );

    // A reinstall writes the lists and the record together, on the same row.
    let again = install(
        &repo,
        owner,
        &["home.example.test"],
        &["svc/token"],
        &stored.owner_added,
    )
    .await
    .expect("reinstall");
    assert_eq!(again, module);
    assert_eq!(
        repo.get_user_module_grants(owner, NAME)
            .await
            .unwrap()
            .unwrap(),
        stored,
        "a reinstall that carries the owner's grants changes neither the lists nor the record"
    );

    // Removing the host removes it from the record.
    let cleared = repo
        .update_module_allowed_hosts(module, owner, &[], &beyond)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cleared.previous, v(&["home.example.test"]));
    assert!(cleared.owner_added.is_empty());
    let after = repo
        .get_user_module_grants(owner, NAME)
        .await
        .unwrap()
        .unwrap();
    assert!(after.hosts.is_empty() && after.owner_added.hosts.is_empty());
    assert_eq!(
        after.owner_added.secrets,
        v(&["svc/token"]),
        "the other grant is untouched"
    );
}

#[tokio::test]
async fn an_inherited_entry_is_never_recorded_as_the_owners() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ModuleRepository::new(pool.clone());
    let owner = seed_user(&pool).await;
    let module = install(
        &repo,
        owner,
        &["api.example.test"],
        &["svc/token"],
        &OwnerAddedGrants::default(),
    )
    .await
    .unwrap();

    // The owner restates what the template gave and adds one host.
    let change = repo
        .update_module_allowed_hosts(
            module,
            owner,
            &v(&["api.example.test", "mine.example.test"]),
            &beyond,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(change.owner_added, v(&["mine.example.test"]));
    // Restating it again changes nothing.
    let again = repo
        .update_module_allowed_hosts(
            module,
            owner,
            &v(&["api.example.test", "mine.example.test"]),
            &beyond,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.owner_added, v(&["mine.example.test"]));
}

#[tokio::test]
async fn a_record_that_names_an_entry_outside_its_list_is_refused() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ModuleRepository::new(pool.clone());
    let owner = seed_user(&pool).await;
    let lying = OwnerAddedGrants {
        hosts: v(&["not-granted.example.test"]),
        ..OwnerAddedGrants::default()
    };
    let refused = install(&repo, owner, &["api.example.test"], &[], &lying).await;
    assert!(
        refused.is_err(),
        "the record may only name entries of its list"
    );
    assert!(repo
        .get_user_module_grants(owner, NAME)
        .await
        .unwrap()
        .is_none());
}
