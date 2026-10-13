//! Two things the operator's tools could not do (2026-10-13).
//!
//! * A workflow's actor could not be read: `get_workflow` and
//!   `get_workflow_identity` returned none, so "create a sibling workflow as
//!   the same actor" meant inferring the binding from `list_actors` counts.
//! * `actor_remember` could not set `metadata`. A module's `__memory_write__`
//!   envelope can stamp `metadata.kind`; the operator's tool answered
//!   `ignored_arguments: ["metadata"]`, so a row written by hand for a test
//!   could not carry the label that keeps synthetic rows out of recall.
//!
//! Driven through the real tool handlers against a real database.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

use controller::mcp::types::JsonRpcResponse;
use controller::mcp::McpState;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'gaps')")
        .bind(id)
        .bind(format!("gaps-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

async fn seed_actor(pool: &Pool<Postgres>, user: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user: Uuid, actor: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, actor_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, $3, $4, '{\"nodes\":[],\"edges\":[]}', 'talos://test-module', 'draft')",
    )
    .bind(id)
    .bind(user)
    .bind(actor)
    .bind(format!("gaps-{id}"))
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

fn refused(resp: &JsonRpcResponse) -> bool {
    resp.error.is_some()
        || resp
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool)
            == Some(true)
}

async fn get_workflow(state: &Arc<McpState>, user: Uuid, args: Value) -> Value {
    let resp = controller::mcp::workflows::dispatch(
        "get_workflow",
        Some(json!(1)),
        &args,
        state.clone(),
        agent(user),
    )
    .await
    .expect("get_workflow is dispatched");
    assert!(!refused(&resp), "{resp:?}");
    text_json(&resp)
}

async fn identity(state: &Arc<McpState>, user: Uuid, workflow: Uuid) -> Value {
    let resp = controller::mcp::configuration::dispatch(
        "get_workflow_identity",
        Some(json!(1)),
        &json!({ "workflow_id": workflow.to_string() }),
        state,
        agent(user),
    )
    .await
    .expect("get_workflow_identity is dispatched");
    assert!(!refused(&resp), "{resp:?}");
    text_json(&resp)
}

#[tokio::test]
async fn a_workflows_actor_can_be_read_and_no_binding_is_said_to_be_none() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user, "Assistant").await;
    let bound = seed_workflow(&pool, user, Some(actor)).await;
    let unbound = seed_workflow(&pool, user, None).await;
    let state = Arc::new(mcp_state(pool.clone()).await);

    let want_bound = json!({ "bound": true, "actor_id": actor.to_string(), "name": "Assistant" });
    let want_unbound = json!({ "bound": false });

    for view in [json!({}), json!({ "view": "summary" })] {
        let mut args = view.clone();
        args["workflow_id"] = json!(bound.to_string());
        assert_eq!(
            get_workflow(&state, user, args).await["actor"],
            want_bound,
            "{view}"
        );
        let mut args = view.clone();
        args["workflow_id"] = json!(unbound.to_string());
        assert_eq!(
            get_workflow(&state, user, args).await["actor"],
            want_unbound,
            "{view}"
        );
    }
    assert_eq!(identity(&state, user, bound).await["actor"], want_bound);
    assert_eq!(identity(&state, user, unbound).await["actor"], want_unbound);
}

/// The name is read owner-scoped. A workflow row that names an actor the
/// caller does not own (a row that should not exist) shows the id it holds
/// and says the actor was not found; it never shows another user's name.
#[tokio::test]
async fn an_actor_that_is_not_the_callers_is_not_named() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let foreign_actor = seed_actor(&pool, stranger, "Somebody else's").await;
    let workflow = seed_workflow(&pool, user, Some(foreign_actor)).await;
    let state = Arc::new(mcp_state(pool.clone()).await);

    let reply = get_workflow(&state, user, json!({ "workflow_id": workflow.to_string() })).await;
    assert_eq!(
        reply["actor"],
        json!({ "bound": true, "actor_id": foreign_actor.to_string(), "name": null, "actor_found": false })
    );
    assert!(!reply.to_string().contains("Somebody else's"));
}

/// Register the actor-memory crypto hook. A process-global `OnceLock` bound
/// to THIS test's database, so at most one test in the binary may call it;
/// the other tests here write no memory.
async fn register_crypto(pool: &Pool<Postgres>) {
    let secrets =
        Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"));
    secrets.initialize().await.expect("initialize secrets");
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(secrets),
    ));
}

async fn remember(state: &Arc<McpState>, user: Uuid, args: Value) -> JsonRpcResponse {
    controller::mcp::actor::dispatch("actor_remember", Some(json!(1)), &args, state, agent(user))
        .await
        .expect("actor_remember is dispatched")
}

async fn stored_metadata(pool: &Pool<Postgres>, actor: Uuid, key: &str) -> Option<Option<Value>> {
    sqlx::query_scalar::<_, Option<Value>>(
        "SELECT metadata FROM actor_memory WHERE actor_id = $1 AND key = $2",
    )
    .bind(actor)
    .bind(key)
    .fetch_optional(pool)
    .await
    .expect("read metadata")
}

#[tokio::test]
async fn actor_remember_stores_metadata_as_a_workflows_memory_write_does() {
    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user, "Assistant").await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let args = |key: &str, metadata: Option<Value>| {
        let mut args = json!({ "actor_id": actor.to_string(), "key": key,
                               "value": { "text": "a made-up brief" }, "memory_type": "semantic" });
        if let Some(metadata) = metadata {
            args["metadata"] = metadata;
        }
        args
    };

    // The argument is the tool's own now: declared in its schema, so the
    // dispatcher no longer reports it under `ignored_arguments`.
    let schema = controller::mcp::actor::tool_schemas()
        .into_iter()
        .find(|t| t["name"] == "actor_remember")
        .expect("actor_remember is a tool");
    assert!(
        schema["inputSchema"]["properties"]["metadata"].is_object(),
        "{schema}"
    );

    let metadata = json!({ "kind": "daily_brief", "source": "by hand" });
    let resp = remember(&state, user, args("brief/one", Some(metadata.clone()))).await;
    assert!(!refused(&resp), "{resp:?}");
    assert_eq!(text_json(&resp)["metadata_stored"], true);
    assert_eq!(
        stored_metadata(&pool, actor, "brief/one").await,
        Some(Some(metadata))
    );

    // Omitted: no metadata, as before.
    let resp = remember(&state, user, args("brief/two", None)).await;
    assert!(!refused(&resp), "{resp:?}");
    assert_eq!(text_json(&resp)["metadata_stored"], false);
    assert_eq!(stored_metadata(&pool, actor, "brief/two").await, Some(None));

    // Anything that is not an object is refused, and nothing is written.
    for (what, bad) in [
        ("a string", json!("daily_brief")),
        ("an array", json!(["daily_brief"])),
        ("a number", json!(7)),
    ] {
        let key = format!("brief/bad-{}", what.replace(' ', "-"));
        let resp = remember(&state, user, args(&key, Some(bad))).await;
        assert!(refused(&resp), "{what}: {resp:?}");
        assert!(
            error_message(&resp).contains("metadata must be an object"),
            "{what}"
        );
        assert_eq!(
            stored_metadata(&pool, actor, &key).await,
            None,
            "{what}: a row was written"
        );
    }

    // An explicit null is an omitted argument.
    let resp = remember(&state, user, args("brief/null", Some(Value::Null))).await;
    assert!(!refused(&resp), "{resp:?}");
    assert_eq!(
        stored_metadata(&pool, actor, "brief/null").await,
        Some(None)
    );

    // The envelope's size limit, with the envelope's words.
    let big = json!({ "kind": "x", "pad": "p".repeat(17 * 1024) });
    let resp = remember(&state, user, args("brief/big", Some(big))).await;
    assert!(refused(&resp), "{resp:?}");
    assert!(
        error_message(&resp).contains("metadata too large"),
        "{}",
        error_message(&resp)
    );
    assert_eq!(stored_metadata(&pool, actor, "brief/big").await, None);
}
