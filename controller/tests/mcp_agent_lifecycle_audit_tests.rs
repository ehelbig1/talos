//! An MCP agent credential is never created or destroyed without its record.
//!
//! Package BW (2026-09-16). MCP agent tokens are the long-lived bearer
//! credentials MCP-1201 treats as the riskiest on the platform. The GraphQL
//! `revokeMcpAgent` mutation deleted the `mcp_agents` row and wrote nothing,
//! and because that row was the only place the agent's name, role and
//! connection history lived, a revoked credential left no trace — measured on
//! the reference deployment: two `registered` admin events, one remaining row,
//! no record of the other's revocation. Registration wrote its record from a
//! detached task after the insert returned, so it could be lost too.
//!
//! These tests drive the two functions the resolvers call
//! (`talos_api::schema::actors::mutations::{register_mcp_agent_recorded,
//! revoke_mcp_agent_recorded}`) against real rows and read the results back
//! from the tables: each change commits with exactly one event carrying what
//! the row held, a refused change writes nothing, and a failed audit write
//! leaves the credential exactly as it was.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::PgPool;
use talos_api::schema::actors::mutations::{
    register_mcp_agent_recorded, revoke_mcp_agent_recorded, AgentRegistration,
};
use talos_system_repo::NewAgent;
use uuid::Uuid;

async fn user(pool: &PgPool, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'bw')")
        .bind(id)
        .bind(format!("bw-{tag}-{id}@example.test"))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn role(pool: &PgPool) -> (Uuid, String) {
    sqlx::query_as("SELECT id, name FROM agent_roles ORDER BY name LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("a migrated schema seeds agent_roles")
}

async fn register(pool: &PgPool, user_id: Uuid, name: &str) -> (Uuid, AgentRegistration) {
    let (role_id, role_name) = role(pool).await;
    let id = Uuid::new_v4();
    let outcome = register_mcp_agent_recorded(
        pool,
        NewAgent {
            id,
            name,
            role_id,
            token_hash: "$2b$10$not-a-real-hash",
            token_lookup_hash: &format!("lookup-{id}"),
            user_id,
        },
        &role_name,
    )
    .await
    .expect("registration");
    (id, outcome)
}

async fn events(pool: &PgPool, agent_id: Uuid) -> Vec<(String, Uuid, String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type, user_id, summary, details FROM admin_event_log \
         WHERE resource_type = 'mcp_agent' AND resource_id = $1 ORDER BY created_at, id",
    )
    .bind(agent_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn agent_exists(pool: &PgPool, agent_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mcp_agents WHERE id = $1)")
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn registration_commits_with_its_record_and_a_duplicate_writes_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = user(&pool, "owner").await;
    let (_, role_name) = role(&pool).await;

    let (id, outcome) = register(&pool, owner, "bw-agent").await;
    assert_eq!(outcome, AgentRegistration::Registered);
    assert!(agent_exists(&pool, id).await);
    let ev = events(&pool, id).await;
    assert_eq!(ev.len(), 1, "exactly one registration record: {ev:?}");
    assert_eq!(ev[0].0, "registered");
    assert_eq!(ev[0].1, owner);
    assert_eq!(ev[0].3["role"], role_name.as_str());

    // A duplicate name is refused and leaves no row and no record.
    let (dup, outcome) = register(&pool, owner, "bw-agent").await;
    assert_eq!(outcome, AgentRegistration::DuplicateName);
    assert!(!agent_exists(&pool, dup).await);
    assert!(events(&pool, dup).await.is_empty());
}

#[tokio::test]
async fn revocation_commits_with_a_record_of_what_the_row_held() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = user(&pool, "owner").await;
    let (_, role_name) = role(&pool).await;
    let (id, _) = register(&pool, owner, "bw-revoked").await;
    sqlx::query(
        "UPDATE mcp_agents SET last_connected_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    let created_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT created_at FROM mcp_agents WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let revoked = revoke_mcp_agent_recorded(&pool, id, owner)
        .await
        .expect("revocation")
        .expect("the owner's agent is revoked");
    assert_eq!(revoked.name, "bw-revoked");
    assert_eq!(revoked.role, role_name);
    assert_eq!(revoked.created_at, created_at);
    assert!(revoked.last_connected_at.is_some());

    assert!(!agent_exists(&pool, id).await, "the credential row is gone");
    let ev = events(&pool, id).await;
    assert_eq!(ev.len(), 2, "registered + revoked: {ev:?}");
    assert_eq!(ev[1].0, "revoked");
    assert_eq!(ev[1].1, owner);
    assert!(
        ev[1].2.contains("bw-revoked"),
        "summary names the agent: {}",
        ev[1].2
    );
    assert_eq!(ev[1].3["role"], role_name.as_str());
    assert!(ev[1].3["created_at"].is_string());
    assert!(ev[1].3["last_connected_at"].is_string());

    // Revoking again finds nothing and records nothing more.
    assert!(revoke_mcp_agent_recorded(&pool, id, owner)
        .await
        .unwrap()
        .is_none());
    assert_eq!(events(&pool, id).await.len(), 2);
}

#[tokio::test]
async fn another_users_agent_is_not_found_and_nothing_is_written() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = user(&pool, "owner").await;
    let stranger = user(&pool, "stranger").await;
    let (id, _) = register(&pool, owner, "bw-kept").await;

    assert!(revoke_mcp_agent_recorded(&pool, id, stranger)
        .await
        .unwrap()
        .is_none());
    assert!(revoke_mcp_agent_recorded(&pool, Uuid::new_v4(), owner)
        .await
        .unwrap()
        .is_none());
    assert!(agent_exists(&pool, id).await, "a stranger cannot revoke it");
    assert_eq!(
        events(&pool, id).await.len(),
        1,
        "only the registration record"
    );
}

#[tokio::test]
async fn a_revocation_whose_record_cannot_be_written_does_not_revoke() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = user(&pool, "owner").await;
    let (id, _) = register(&pool, owner, "bw-atomic").await;

    // Make the audit append fail on this throwaway clone.
    sqlx::query("ALTER TABLE admin_event_log RENAME TO admin_event_log_unavailable")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        revoke_mcp_agent_recorded(&pool, id, owner).await.is_err(),
        "a revocation without its record must be reported as failed"
    );
    assert!(
        agent_exists(&pool, id).await,
        "the DELETE must roll back with the failed record"
    );

    // The same failure refuses a registration and leaves no credential.
    let (role_id, role_name) = role(&pool).await;
    let new_id = Uuid::new_v4();
    let lookup = format!("lookup-{new_id}");
    let r = register_mcp_agent_recorded(
        &pool,
        NewAgent {
            id: new_id,
            name: "bw-unrecorded",
            role_id,
            token_hash: "$2b$10$not-a-real-hash",
            token_lookup_hash: &lookup,
            user_id: owner,
        },
        &role_name,
    )
    .await;
    assert!(r.is_err(), "a registration without its record must fail");
    assert!(
        !agent_exists(&pool, new_id).await,
        "no credential without a record"
    );
}
