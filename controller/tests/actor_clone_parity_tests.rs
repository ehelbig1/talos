//! One clone, two surfaces (package BM, 2026-09-15).
//!
//! The GraphQL `cloneActor` mutation (the web UI's) had drifted from the MCP
//! `clone_actor` tool: no user capability-ceiling gate, no per-user actor
//! limit, and the source's secret grants, budget policy and approval policies
//! silently dropped. Both now call `talos_actor_lifecycle_service::clone_actor`;
//! these tests drive that function against a real clone of the migrated schema
//! and read every outcome back from the tables. The GraphQL resolver itself has
//! no harness here; its wiring is pinned textually at the bottom.
//!
//! DB tests on the `common` harness, so CTRL_TESTS, not TC_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_actor_lifecycle_service::{
    clone_actor, CloneActorError, CloneActorRequest, CloneOrigin, MAX_ACTORS_PER_USER,
};
use talos_actor_repository::ActorRepository;
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>, grant: Option<&str>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'clone parity')",
    )
    .bind(id)
    .bind(format!("clone-parity-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    if let Some(world) = grant {
        sqlx::query(
            "INSERT INTO user_capability_grants (user_id, max_capability_world) VALUES ($1, $2)",
        )
        .bind(id)
        .bind(world)
        .execute(pool)
        .await
        .expect("seed grant");
    }
    id
}

async fn seed_source(pool: &Pool<Postgres>, user: Uuid, world: &str, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, status, secret_grants, \
                             max_llm_tier, egress_scope, max_write_ceiling) \
         VALUES ($1, $2, $3, $4, $5, ARRAY['oauth/gmail'], 'tier1', 'public', 'readonly')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("source-{id}"))
    .bind(world)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed source actor");
    sqlx::query(
        "INSERT INTO actor_budget_policies (actor_id, max_executions_per_hour, max_fuel_per_execution) \
         VALUES ($1, 7, 12345)",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed budget");
    sqlx::query(
        "INSERT INTO actor_approval_policies (actor_id, trigger_condition, approval_mode) \
         VALUES ($1, 'always', 'block')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed approval policy");
    id
}

fn req(user: Uuid, source: Uuid, name: Option<&str>) -> CloneActorRequest {
    CloneActorRequest {
        user_id: user,
        source_actor_id: source,
        new_name: name.map(str::to_string),
        description_override: None,
        origin: CloneOrigin::Dashboard,
    }
}

async fn actor_count(pool: &Pool<Postgres>, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM actors WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A dashboard clone carries everything the MCP clone always carried.
#[tokio::test]
async fn a_clone_carries_grants_ceilings_budget_and_approval_policies() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool, Some("automation-node")).await;
    let source = seed_source(&pool, user, "agent-node", "active").await;
    let repo = ActorRepository::new(pool.clone());

    let out = clone_actor(&pool, &repo, req(user, source, None))
        .await
        .expect("clone succeeds");
    assert!(out.name.starts_with("Copy of source-"), "{}", out.name);
    assert_eq!(out.budget_copied, Some(true));
    assert_eq!(out.approval_policies_copied, Some(1));
    assert_eq!(out.secret_grants_copied, 1);
    assert!(out.readings.complete());

    let (world, grants, tier, egress, ceiling): (String, Vec<String>, String, Option<String>, String) =
        sqlx::query_as(
            "SELECT max_capability_world, secret_grants, max_llm_tier, egress_scope, max_write_ceiling \
             FROM actors WHERE id = $1",
        )
        .bind(out.new_actor_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(world, "agent-node");
    assert_eq!(grants, vec!["oauth/gmail".to_string()]);
    assert_eq!(
        (tier.as_str(), egress.as_deref(), ceiling.as_str()),
        ("tier1", Some("public"), "readonly")
    );

    let (per_hour, fuel): (Option<i32>, Option<i64>) = sqlx::query_as(
        "SELECT max_executions_per_hour, max_fuel_per_execution FROM actor_budget_policies WHERE actor_id = $1",
    )
    .bind(out.new_actor_id)
    .fetch_one(&pool)
    .await
    .expect("the spend ceiling travelled with the clone");
    assert_eq!((per_hour, fuel), (Some(7), Some(12345)));
    let policies: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM actor_approval_policies WHERE actor_id = $1")
            .bind(out.new_actor_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(policies, 1, "the approval gate travelled with the clone");
}

/// Revoking a grant does not lower existing actors — so a clone must be refused
/// against the user's CURRENT ceiling, and write nothing.
#[tokio::test]
async fn a_source_above_the_current_ceiling_is_refused_and_writes_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool, Some("network-node")).await;
    let source = seed_source(&pool, user, "automation-node", "active").await;
    let repo = ActorRepository::new(pool.clone());
    let before = actor_count(&pool, user).await;

    let err = clone_actor(&pool, &repo, req(user, source, Some("escalated")))
        .await
        .expect_err("refused");
    assert!(
        matches!(err, CloneActorError::CeilingExceeded { .. }),
        "{err:?}"
    );
    assert_eq!(actor_count(&pool, user).await, before);

    // CONTROL: the same source for a user whose grant covers it.
    sqlx::query("UPDATE user_capability_grants SET max_capability_world = 'automation-node' WHERE user_id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    clone_actor(&pool, &repo, req(user, source, Some("escalated")))
        .await
        .expect("admitted once the grant covers it");
    assert_eq!(actor_count(&pool, user).await, before + 1);
}

/// No grant row is the conservative default (`http-node`), not a pass.
#[tokio::test]
async fn a_user_with_no_grant_row_gets_the_conservative_default() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool, None).await;
    let high = seed_source(&pool, user, "agent-node", "active").await;
    let low = seed_source(&pool, user, "minimal-node", "active").await;
    let repo = ActorRepository::new(pool.clone());
    assert!(matches!(
        clone_actor(&pool, &repo, req(user, high, None)).await,
        Err(CloneActorError::CeilingExceeded { .. })
    ));
    clone_actor(&pool, &repo, req(user, low, None))
        .await
        .expect("within http-node");
}

/// Terminate is irreversible; a clone would reactivate it.
#[tokio::test]
async fn a_terminated_actor_is_not_a_clone_source() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool, Some("automation-node")).await;
    let dead = seed_source(&pool, user, "minimal-node", "terminated").await;
    let archived = seed_source(&pool, user, "minimal-node", "archived").await;
    let repo = ActorRepository::new(pool.clone());
    assert!(matches!(
        clone_actor(&pool, &repo, req(user, dead, None)).await,
        Err(CloneActorError::SourceNotFound)
    ));
    // CONTROL: archived stays cloneable (neither surface refused it).
    clone_actor(&pool, &repo, req(user, archived, None))
        .await
        .expect("archived source clones");
}

/// Another user's actor is invisible, not merely refused.
#[tokio::test]
async fn another_users_actor_is_not_found() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool, Some("automation-node")).await;
    let stranger = seed_user(&pool, Some("automation-node")).await;
    let source = seed_source(&pool, owner, "minimal-node", "active").await;
    let repo = ActorRepository::new(pool.clone());
    assert!(matches!(
        clone_actor(&pool, &repo, req(stranger, source, None)).await,
        Err(CloneActorError::SourceNotFound)
    ));
    assert_eq!(actor_count(&pool, stranger).await, 0);
}

/// The per-user limit is enforced by the INSERT itself.
#[tokio::test]
async fn the_actor_limit_refuses_the_clone_at_the_cap() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool, Some("automation-node")).await;
    let source = seed_source(&pool, user, "minimal-node", "active").await;
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, status) \
         SELECT gen_random_uuid(), $1, 'filler-' || g, 'minimal-node', 'active' \
         FROM generate_series(1, $2) g",
    )
    .bind(user)
    .bind(MAX_ACTORS_PER_USER - 1)
    .execute(&pool)
    .await
    .expect("fill to the cap");
    assert_eq!(actor_count(&pool, user).await, MAX_ACTORS_PER_USER);
    let repo = ActorRepository::new(pool.clone());
    assert!(matches!(
        clone_actor(&pool, &repo, req(user, source, Some("one-too-many"))).await,
        Err(CloneActorError::LimitReached)
    ));
    assert_eq!(actor_count(&pool, user).await, MAX_ACTORS_PER_USER);
}

/// TEXTUAL pins (stated): both surfaces call the one implementation and neither
/// re-grows its own INSERT or ceiling read.
#[test]
fn both_surfaces_call_the_shared_clone() {
    let gql = include_str!("../../talos-api/src/schema/actors/mutations.rs");
    let start = gql.find("async fn clone_actor(").expect("gql resolver");
    let body = &gql[start..start + gql[start..].find("\n    async fn ").expect("next fn")];
    assert!(
        body.contains("talos_actor_lifecycle_service::clone_actor("),
        "{body}"
    );
    assert!(
        !body.contains("INSERT INTO actors") && !body.contains("insert_actor"),
        "{body}"
    );

    let mcp = include_str!("../../talos-mcp-handlers/src/actor.rs");
    let start = mcp
        .find("async fn handle_clone_actor(")
        .expect("mcp handler");
    let body = &mcp[start..start + mcp[start..].find("\nasync fn ").expect("next fn")];
    assert!(
        body.contains("talos_actor_lifecycle_service::clone_actor("),
        "{body}"
    );
    assert!(
        !body.contains("insert_actor_with_grants_and_limit_check"),
        "{body}"
    );
    assert!(!body.contains("ceiling_permits"), "{body}");
}
