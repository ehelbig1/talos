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
//! The record is also READ back (2026-10-04): `get_module_info` shows the
//! three lists beside the grants they describe. Those tests go through the
//! real tool, so they cover the handler's call site and its ownership scope,
//! not only the repository read.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
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

/// Call `get_module_info` through the real tool, as `who`.
async fn module_info(
    state: &controller::mcp::McpState,
    module: Uuid,
    who: Uuid,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::modules::dispatch(
        "get_module_info",
        Some(json!(1)),
        &json!({ "module_id": module.to_string() }),
        state,
        agent(who),
    )
    .await
    .expect("get_module_info is dispatched")
}

/// The record is visible where the grants are read (2026-10-04). Until then
/// it appeared only in the reply of the three update tools and in a
/// reinstall's `grants_kept_as_owner_added`, so nothing let an owner look at
/// a module and see which of its grants a reinstall would keep.
#[tokio::test]
async fn module_info_shows_which_grants_the_owner_added() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = mcp_state(pool.clone()).await;
    let repo = ModuleRepository::new(pool.clone());
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;

    let module = install(&repo, owner, &[], &[], &OwnerAddedGrants::default())
        .await
        .expect("first install");
    repo.update_module_allowed_hosts(module, owner, &v(&["home.example.test"]), &beyond)
        .await
        .unwrap()
        .expect("the owner's module");
    repo.update_module_allowed_secrets(module, owner, &v(&["svc/token"]), &beyond)
        .await
        .unwrap()
        .expect("the owner's module");

    // The repository read carries the record the writers stored.
    let stored = repo
        .get_user_module_grants(owner, NAME)
        .await
        .unwrap()
        .unwrap();
    let read = repo
        .get_wasm_module_info(module, owner)
        .await
        .unwrap()
        .expect("the owner reads their module");
    assert_eq!(read.owner_added, stored.owner_added);

    // The tool shows each list with the grant it describes, and the legend.
    let body = text_json(&module_info(&state, module, owner).await);
    assert_eq!(body["allowed_hosts"], json!(["home.example.test"]));
    assert_eq!(body["owner_added_hosts"], json!(["home.example.test"]));
    assert_eq!(body["allowed_secrets"], json!(["svc/token"]));
    assert_eq!(body["owner_added_secrets"], json!(["svc/token"]));
    // POST came with the install, so it is in the grant and not in the record.
    assert_eq!(body["allowed_methods"], json!(["POST"]));
    assert_eq!(body["owner_added_methods"], json!([]));
    let note = body["owner_added_note"].as_str().expect("the legend");
    assert!(
        note.contains("a catalog reinstall keeps such an entry"),
        "{note}"
    );

    // Someone else reads neither the module nor its record.
    assert!(repo
        .get_wasm_module_info(module, stranger)
        .await
        .unwrap()
        .is_none());
    let refused = module_info(&state, module, stranger).await;
    let message = error_message(&refused);
    assert!(message.contains("not found or access denied"), "{message}");
    assert!(!message.contains("home.example.test"), "{message}");
}

/// A copy granted before the record existed holds grants and an empty
/// record, and a shared catalog row never has one. Both read as three empty
/// lists — present, not omitted: for the copy that is the answer that says a
/// reinstall keeps its grants only as far as the template grants them.
#[tokio::test]
async fn nothing_recorded_reads_as_three_empty_lists() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = mcp_state(pool.clone()).await;
    let repo = ModuleRepository::new(pool.clone());
    let owner = seed_user(&pool).await;

    let legacy = install(
        &repo,
        owner,
        &["api.example.test"],
        &["svc/token"],
        &OwnerAddedGrants::default(),
    )
    .await
    .expect("a copy with grants and no record");
    let shared: Uuid = sqlx::query_scalar(
        "INSERT INTO modules (name, kind, user_id, capability_world, category, \
                              allowed_hosts, source_code, wasm_bytes) \
         VALUES ('Shared: Example', 'catalog', NULL, 'http-node', 'test', \
                 ARRAY['api.example.test'], 'fn run() {}', '\\x00'::bytea) \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed a shared catalog row");

    for module in [legacy, shared] {
        let body = text_json(&module_info(&state, module, owner).await);
        assert_eq!(body["allowed_hosts"], json!(["api.example.test"]), "{body}");
        for key in [
            "owner_added_hosts",
            "owner_added_methods",
            "owner_added_secrets",
        ] {
            assert_eq!(body[key], json!([]), "{key} of {module}: {body}");
        }
        assert!(body["owner_added_note"].is_string(), "{body}");
    }
}
