//! Package CC (2026-09-17): an approval policy on a trigger nothing evaluates
//! is refused at creation. Until then `add_actor_approval_policy` stored
//! `new_external_host` / `database_write` / `email_send` / `new_secret_access`
//! policies that had no effect. These tests drive the REAL MCP dispatch over a
//! real `McpState` and read `actor_approval_policies` back.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use common::{create_test_user, setup_test_context};
use mcp_common::{agent, error_message, mcp_state, text_json};
use uuid::Uuid;

async fn seed_actor(pool: &sqlx::PgPool, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, status) \
         VALUES ($1, $2, $3, 'minimal-node', 'active')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("cc-actor-{}", &id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("seed actor");
    id
}

async fn policy_count(pool: &sqlx::PgPool, actor: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM actor_approval_policies WHERE actor_id = $1")
        .bind(actor)
        .fetch_one(pool)
        .await
        .expect("count policies")
}

async fn add_policy(
    state: &controller::mcp::McpState,
    user: Uuid,
    actor: Uuid,
    trigger: &str,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::actor::dispatch(
        "add_actor_approval_policy",
        Some(serde_json::json!(1)),
        &serde_json::json!({
            "actor_id": actor.to_string(),
            "trigger_condition": trigger,
            "approval_mode": "log",
        }),
        state,
        agent(user),
    )
    .await
    .expect("add_actor_approval_policy is dispatched")
}

#[tokio::test]
async fn unevaluated_triggers_are_refused_and_store_nothing() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "cc_refused@example.com").await;
    let actor = seed_actor(&pool, user).await;
    let state = mcp_state(pool.clone()).await;

    for trigger in [
        "new_external_host",
        "database_write",
        "email_send",
        "new_secret_access",
    ] {
        let resp = add_policy(&state, user, actor, trigger).await;
        let msg = error_message(&resp);
        assert!(msg.contains(trigger), "{trigger}: {msg}");
        assert!(msg.contains("not evaluated"), "{trigger}: {msg}");
    }
    assert_eq!(
        policy_count(&pool, actor).await,
        0,
        "a refused policy is not stored"
    );
}

#[tokio::test]
async fn enforced_triggers_are_still_accepted() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "cc_accepted@example.com").await;
    let actor = seed_actor(&pool, user).await;
    let state = mcp_state(pool.clone()).await;

    let resp = add_policy(&state, user, actor, "first_workflow_deploy").await;
    assert_eq!(
        text_json(&resp).get("enforcement").and_then(|v| v.as_str()),
        Some("enabled")
    );
    let resp = add_policy(&state, user, actor, "workflow_id != \"\"").await;
    assert_eq!(
        text_json(&resp).get("enforcement").and_then(|v| v.as_str()),
        Some("enabled_for_publish_version_only")
    );
    assert_eq!(policy_count(&pool, actor).await, 2);
}
