//! A capability grant admits exactly the actor ceiling worlds (package BR,
//! 2026-09-16).
//!
//! `user_capability_grants.max_capability_world`'s CHECK had drifted from
//! `talos_capability_world::ACTOR_CEILING_WORLDS` since MCP-816/817
//! (2026-05-14): it refused `llm-node` and `agent-node` — both accepted by the
//! MCP and GraphQL grant validators, so every such grant failed at the INSERT
//! with a generic error — and still admitted the dead `standard-node` /
//! `full-node` labels. Migration `20260916100000` realigns it; these tests pin
//! the constraint EQUAL to the Rust list, drive the production writer and the
//! one ceiling read (`ActorRepository::user_capability_ceiling`), and replay the
//! migration over a row holding a dead label.
//!
//! DB tests on the `common` harness, so CTRL_TESTS, not TC_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use std::collections::BTreeSet;
use talos_actor_repository::ActorRepository;
use talos_capability_world::{ceiling_permits, ACTOR_CEILING_WORLDS};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'ucg')")
        .bind(id)
        .bind(format!("ucg-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

async fn constraint_worlds(pool: &Pool<Postgres>) -> BTreeSet<String> {
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conrelid = 'user_capability_grants'::regclass AND conname = 'ucg_world_check'",
    )
    .fetch_one(pool)
    .await
    .expect("ucg_world_check exists");
    def.split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

fn is_check_violation(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<sqlx::Error>()
            .and_then(|s| s.as_database_error())
            .and_then(|d| d.code())
            .is_some_and(|code| code == "23514")
    })
}

/// The pin that outlives this migration: the next change to
/// `ACTOR_CEILING_WORLDS` fails here until a migration follows it.
#[tokio::test]
async fn the_grant_constraint_admits_exactly_the_actor_ceiling_worlds() {
    let (pool, _db) = common::isolated_db_pool().await;
    let stored = constraint_worlds(&pool).await;
    let canonical: BTreeSet<String> = ACTOR_CEILING_WORLDS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        stored, canonical,
        "ucg_world_check and ACTOR_CEILING_WORLDS must name the same set"
    );
}

/// Every canonical ceiling — `llm-node` and `agent-node` above all, the two the
/// old constraint refused — is grantable through the PRODUCTION writer and
/// reads back through the one ceiling read.
#[tokio::test]
async fn every_actor_ceiling_world_can_be_granted_and_read_back() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    let granter = seed_user(&pool).await;
    for world in ACTOR_CEILING_WORLDS {
        let user = seed_user(&pool).await;
        repo.upsert_capability_grant(user, world, granter, Some("BR"))
            .await
            .unwrap_or_else(|e| panic!("granting {world} must succeed: {e:#}"));
        assert_eq!(repo.user_capability_ceiling(user).await.unwrap(), *world);
    }
}

/// The least-privilege shape the drift made impossible: a user granted
/// `agent-node` may create an agent actor and may NOT create an automation one.
#[tokio::test]
async fn an_agent_node_grant_permits_agent_actors_and_nothing_above() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    let user = seed_user(&pool).await;
    repo.upsert_capability_grant(user, "agent-node", user, None)
        .await
        .expect("agent-node grant");
    let ceiling = repo.user_capability_ceiling(user).await.unwrap();
    assert!(ceiling_permits(&ceiling, "agent-node"));
    assert!(!ceiling_permits(&ceiling, "automation-node"));
}

/// Dead and alias labels are refused by the database itself, whatever the
/// caller validated.
#[tokio::test]
async fn dead_ceiling_labels_are_refused_by_the_constraint() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    for label in ["standard-node", "full-node", "trusted-node", "agent_node"] {
        let user = seed_user(&pool).await;
        let err = repo
            .upsert_capability_grant(user, label, user, None)
            .await
            .expect_err(label);
        assert!(is_check_violation(&err), "{label}: {err:#}");
    }
}

/// No grant row is `http-node` (the column DEFAULT), and a non-canonical stored
/// value — now unstorable — still reads `http-node`, never its raw label.
#[tokio::test]
async fn the_ceiling_read_defaults_conservatively() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ActorRepository::new(pool.clone());
    let ungranted = seed_user(&pool).await;
    assert_eq!(
        repo.user_capability_ceiling(ungranted).await.unwrap(),
        "http-node"
    );

    // Defence in depth, driven by removing the constraint on this throwaway clone.
    sqlx::query("ALTER TABLE user_capability_grants DROP CONSTRAINT ucg_world_check")
        .execute(&pool)
        .await
        .unwrap();
    let legacy = seed_user(&pool).await;
    sqlx::query(
        "INSERT INTO user_capability_grants (user_id, max_capability_world) VALUES ($1, 'full-node')",
    )
    .bind(legacy)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repo.user_capability_ceiling(legacy).await.unwrap(),
        "http-node"
    );
}

/// A grant that cannot be READ is an error, never a default — the #661 rule.
/// A defaulted `http-node` is an escalation for a user granted `minimal-node`,
/// persisted into whatever actor the caller then creates.
#[tokio::test]
async fn an_unreadable_grant_is_an_error_not_a_default() {
    let unreachable = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .unwrap();
    let repo = ActorRepository::new(unreachable);
    assert!(repo.user_capability_ceiling(Uuid::new_v4()).await.is_err());
}

/// The migration itself, replayed over the pre-migration shape: a row holding
/// a dead label is rewritten to what every gate already read it as, so the new
/// constraint can be added, and a canonical row is untouched.
#[tokio::test]
async fn the_migration_rewrites_dead_labels_before_constraining() {
    let (pool, _db) = common::isolated_db_pool().await;
    sqlx::query("ALTER TABLE user_capability_grants DROP CONSTRAINT ucg_world_check")
        .execute(&pool)
        .await
        .unwrap();
    let dead = seed_user(&pool).await;
    let live = seed_user(&pool).await;
    for (user, world) in [(dead, "standard-node"), (live, "agent-node")] {
        sqlx::query(
            "INSERT INTO user_capability_grants (user_id, max_capability_world) VALUES ($1, $2)",
        )
        .bind(user)
        .bind(world)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::raw_sql(include_str!(
        "../../migrations/20260916100000_capability_grant_world_check_matches_ceiling_worlds.sql"
    ))
    .execute(&pool)
    .await
    .expect("migration replays over a dead label");

    let repo = ActorRepository::new(pool.clone());
    let world_of = |u: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT max_capability_world FROM user_capability_grants WHERE user_id = $1",
            )
            .bind(u)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(world_of(dead).await, "http-node");
    assert_eq!(world_of(live).await, "agent-node");
    assert_eq!(
        repo.user_capability_ceiling(live).await.unwrap(),
        "agent-node"
    );
    assert_eq!(
        constraint_worlds(&pool).await.len(),
        ACTOR_CEILING_WORLDS.len()
    );
}

/// The rule has ONE home. Textual, stated as such: the raw grant read stays
/// private to the repository, and every former copy calls the shared read.
#[test]
fn every_ceiling_reader_calls_the_one_home() {
    let repo = include_str!("../../talos-actor-repository/src/lib.rs");
    assert!(repo.contains("    async fn read_user_grant_world("));
    assert!(!repo.contains("pub async fn read_user_grant_world("));
    assert!(!repo.contains("get_user_max_capability_world"));
    // Exact call counts, not presence: `talos-api/src/schema/actors/mutations.rs`
    // holds TWO gates (createActor, updateActor), so a presence check stays
    // green when one of them is reverted.
    for (path, src, expected) in [
        (
            "talos-api actors",
            include_str!("../../talos-api/src/schema/actors/mutations.rs"),
            2,
        ),
        (
            "talos-api platform mutations",
            include_str!("../../talos-api/src/schema/platform/mutations.rs"),
            1,
        ),
        (
            "talos-api platform queries",
            include_str!("../../talos-api/src/schema/platform/queries.rs"),
            1,
        ),
        (
            "talos-actor-scaffold",
            include_str!("../../talos-actor-scaffold/src/lib.rs"),
            1,
        ),
        (
            "talos-actor-lifecycle-service clone",
            include_str!("../../talos-actor-lifecycle-service/src/clone.rs"),
            1,
        ),
        (
            "talos-mcp-handlers actor",
            include_str!("../../talos-mcp-handlers/src/actor.rs"),
            1,
        ),
        (
            "talos-mcp-handlers platform",
            include_str!("../../talos-mcp-handlers/src/platform.rs"),
            1,
        ),
    ] {
        assert_eq!(
            src.matches(".user_capability_ceiling(").count(),
            expected,
            "{path} must read the ceiling through the one home at every gate"
        );
        assert!(
            !src.contains("is_actor_ceiling_world(&world)"),
            "{path} re-derives the ceiling rule"
        );
    }
}
