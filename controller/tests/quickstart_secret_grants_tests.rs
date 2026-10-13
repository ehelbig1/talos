//! `get_workflow_quickstart` and `create_workflow` give ONE answer about a
//! workflow's secret grants (2026-10-13).
//!
//! The quickstart asked whether a secret was stored at a path EQUAL to each
//! grant entry. A prefix (`oauth/gmail`) or glob (`chat/*`) grant never is
//! one, so a workflow whose secret was in place was reported unprovisioned,
//! with a blocker and `ready_to_run: false`, while `create_workflow` had said
//! of the same workflow that nothing was missing. The two also filtered on
//! different ownership columns.
//!
//! Both now read one listing (the key paths a dispatch for the caller can
//! read) and judge each grant with one matcher. Driven here through both
//! real handlers against real rows, with a second user's secrets in the
//! table: another user's secret must never satisfy this user's grant.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::sync::Arc;

use mcp_common::{agent, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'grants')",
    )
    .bind(id)
    .bind(format!("grants-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_module(pool: &Pool<Postgres>, user: Uuid, grants: &[&str]) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, wasm_bytes, capability_world, kind, allowed_secrets) \
         VALUES ($1, $2, $3, '\\x00'::bytea, 'secrets-node', 'sandbox', $4)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("grants-module-{id}"))
    .bind(grants.iter().map(|g| (*g).to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await
    .expect("seed module");
    id
}

/// A secret row as the secrets manager writes its two ownership columns: the
/// creator in both. `owner = None` is an ownerless row, which every user's
/// dispatch can read.
async fn seed_secret(pool: &Pool<Postgres>, key_id: Uuid, owner: Option<Uuid>, key_path: &str) {
    sqlx::query(
        "INSERT INTO secrets (id, name, key_path, encrypted_value, encryption_key_id, \
                              owner_user_id, created_by) \
         VALUES ($1, $2, $3, '\\x00'::bytea, $4, $5, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(format!("grants-{}", Uuid::new_v4().simple()))
    .bind(key_path)
    .bind(key_id)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed secret");
}

async fn key_id(pool: &Pool<Postgres>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO encryption_keys (encrypted_key) VALUES ('\\x00'::bytea) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed an encryption key row")
}

/// The `key_path` of every entry of a JSON array of objects.
fn key_paths(entries: &Value) -> Vec<String> {
    entries
        .as_array()
        .expect("an array")
        .iter()
        .map(|e| e["key_path"].as_str().expect("key_path").to_string())
        .collect()
}

const GRANTS: [&str; 7] = [
    "svc/token",   // exact, stored by the owner
    "oauth/gmail", // prefix; the owner holds a token under it
    "notes/*",     // glob; the owner holds a path under it
    "shared",      // prefix; only an ownerless secret is under it
    "chat/*",      // glob; only ANOTHER user holds a path under it
    "bank/secret", // exact; nobody holds it
    "*",           // everything: never listed, never missing
];

#[tokio::test]
async fn the_quickstart_and_create_workflow_give_one_answer_about_a_workflows_grants() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let key = key_id(&pool).await;
    for path in [
        "svc/token",
        "oauth/gmail/u/a@example.com/access_token",
        "notes/journal/key",
    ] {
        seed_secret(&pool, key, Some(owner), path).await;
    }
    seed_secret(&pool, key, None, "shared/relay/key").await;
    // The stranger's secrets: one under a grant the owner's module declares,
    // and one at the exact path the owner lacks.
    seed_secret(&pool, key, Some(stranger), "chat/token").await;
    seed_secret(&pool, key, Some(stranger), "bank/secret").await;

    let module = seed_module(&pool, owner, &GRANTS).await.to_string();
    let state = Arc::new(mcp_state(pool.clone()).await);

    // The one listing both tools read: the owner's and the ownerless paths,
    // sorted, and nothing of the stranger's.
    assert_eq!(
        state
            .secrets_manager
            .list_dispatch_readable_key_paths(owner)
            .await
            .expect("list"),
        [
            "notes/journal/key",
            "oauth/gmail/u/a@example.com/access_token",
            "shared/relay/key",
            "svc/token",
        ]
    );
    assert_eq!(
        state
            .secrets_manager
            .list_dispatch_readable_key_paths(stranger)
            .await
            .expect("list"),
        ["bank/secret", "chat/token", "shared/relay/key"]
    );

    let created = controller::mcp::workflows::dispatch(
        "create_workflow",
        Some(json!(1)),
        &json!({
            "name": "grants-one-answer",
            "include_config_suggestions": false,
            "nodes": [{ "id": "n1", "module_id": module }],
            "edges": [],
        }),
        state.clone(),
        agent(owner),
    )
    .await
    .expect("create_workflow is dispatched");
    let created = text_json(&created);
    let workflow = created["workflow_id"].as_str().expect("created");
    let missing_at_create: Vec<String> = created["missing_secrets"]
        .as_array()
        .unwrap_or_else(|| panic!("create_workflow reports missing_secrets: {created}"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        missing_at_create,
        ["bank/secret", "chat/*"],
        "the stranger's secrets satisfy nothing of the owner's: {created}"
    );

    let quickstart = controller::mcp::workflows::dispatch(
        "get_workflow_quickstart",
        Some(json!(2)),
        &json!({ "workflow_id": workflow }),
        state.clone(),
        agent(owner),
    )
    .await
    .expect("get_workflow_quickstart is dispatched");
    let quickstart = text_json(&quickstart);

    let verdicts: Vec<(String, Option<bool>)> = quickstart["secrets_status"]
        .as_array()
        .unwrap_or_else(|| panic!("secrets_status: {quickstart}"))
        .iter()
        .map(|s| {
            (
                s["key_path"].as_str().unwrap().to_string(),
                s["provisioned"].as_bool(),
            )
        })
        .collect();
    assert_eq!(
        verdicts,
        [
            ("bank/secret".to_string(), Some(false)),
            ("chat/*".to_string(), Some(false)),
            ("notes/*".to_string(), Some(true)),
            ("oauth/gmail".to_string(), Some(true)),
            ("shared".to_string(), Some(true)),
            ("svc/token".to_string(), Some(true)),
        ],
        "a prefix or glob grant with a secret behind it is provisioned; \
         another user's secret is not behind it: {quickstart}"
    );

    let blocked: Vec<String> = key_paths(&Value::Array(
        quickstart["blockers"]
            .as_array()
            .expect("blockers")
            .iter()
            .filter(|b| b["type"] == "missing_secret")
            .cloned()
            .collect(),
    ));
    assert_eq!(
        blocked, missing_at_create,
        "the two tools disagree about the same workflow"
    );
    assert_eq!(quickstart["ready_to_run"], false, "{quickstart}");
    assert!(quickstart.get("measurement").is_none(), "{quickstart}");

    // Nothing the stranger holds is named anywhere in either reply.
    for reply in [created.to_string(), quickstart.to_string()] {
        assert!(!reply.contains("chat/token"), "{reply}");
    }
}

/// With every declared grant satisfied, nothing blocks: before the change a
/// workflow whose only grants were a prefix and a glob could never be
/// `ready_to_run` here, whatever was stored.
#[tokio::test]
async fn a_workflow_whose_prefix_and_glob_grants_are_satisfied_is_ready_to_run() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let key = key_id(&pool).await;
    seed_secret(
        &pool,
        key,
        Some(owner),
        "oauth/gmail/u/a@example.com/access_token",
    )
    .await;
    seed_secret(&pool, key, Some(owner), "notes/journal/key").await;
    let module = seed_module(&pool, owner, &["oauth/gmail", "notes/*"])
        .await
        .to_string();
    let state = Arc::new(mcp_state(pool.clone()).await);

    let created = controller::mcp::workflows::dispatch(
        "create_workflow",
        Some(json!(1)),
        &json!({
            "name": "grants-satisfied",
            "include_config_suggestions": false,
            "nodes": [{ "id": "n1", "module_id": module }],
            "edges": [],
        }),
        state.clone(),
        agent(owner),
    )
    .await
    .expect("create_workflow is dispatched");
    let created = text_json(&created);
    assert_eq!(created["missing_secrets"], json!([]), "{created}");

    let quickstart = controller::mcp::workflows::dispatch(
        "get_workflow_quickstart",
        Some(json!(2)),
        &json!({ "workflow_id": created["workflow_id"] }),
        state,
        agent(owner),
    )
    .await
    .expect("get_workflow_quickstart is dispatched");
    let quickstart = text_json(&quickstart);
    assert!(
        !quickstart["blockers"]
            .as_array()
            .expect("blockers")
            .iter()
            .any(|b| b["type"] == "missing_secret"),
        "{quickstart}"
    );
    assert_eq!(
        quickstart["ready_to_run"], created["ready_to_run"],
        "create: {created}\nquickstart: {quickstart}"
    );
}
