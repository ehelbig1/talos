//! Integration test for the MCP-agent revocation-definition query.
//!
//! `SystemRepository::list_active_agent_ids` is the single source of truth for
//! "which cached MCP tokens are still valid". TWO security-critical consumers
//! depend on it:
//!   * the bcrypt revocation sweep (MCP-991) — evicts cache entries whose
//!     agent is NOT in the returned active set, so a revoked token stops
//!     authenticating faster than its 10 s cache TTL;
//!   * (by the same `is_active = true` definition) the primary auth lookup
//!     `find_active_agent_by_token_lookup_hash`.
//!
//! A regression that drops `is_active = true` from this query would silently
//! let REVOKED MCP tokens survive sweep-eviction (and, if mirrored, primary
//! auth) — a privilege-persistence bug with no compile error. This test pins
//! the definition against a live Postgres.
//!
//! Skipped (green) unless `TALOS_TEST_DATABASE_URL` is set. Run locally:
//!
//! ```bash
//! TALOS_TEST_DATABASE_URL=postgres://… \
//!   cargo test -p talos-system-repo --test revocation_query
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use talos_system_repo::SystemRepository;
use uuid::Uuid;

async fn pool_or_skip() -> Option<Pool<Postgres>> {
    let url = std::env::var("TALOS_TEST_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())?;
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("TALOS_TEST_DATABASE_URL connect"),
    )
}

#[tokio::test]
async fn list_active_agent_ids_excludes_revoked_and_unknown() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };

    // Unique names per run so the suite is safe against the shared migrated DB
    // and re-runs (mcp_agents.name and agent_roles.name are both UNIQUE).
    let suffix = Uuid::new_v4();

    let role_id: Uuid =
        sqlx::query_scalar("INSERT INTO agent_roles (name) VALUES ($1) RETURNING id")
            .bind(format!("revtest-role-{suffix}"))
            .fetch_one(&pool)
            .await
            .expect("seed agent_role");

    let insert_agent = |name: String, active: bool| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO mcp_agents (name, role_id, token_hash, is_active) \
                 VALUES ($1, $2, 'x', $3) RETURNING id",
            )
            .bind(name)
            .bind(role_id)
            .bind(active)
            .fetch_one(&pool)
            .await
            .expect("seed mcp_agent")
        }
    };

    let active_id = insert_agent(format!("revtest-active-{suffix}"), true).await;
    let revoked_id = insert_agent(format!("revtest-revoked-{suffix}"), false).await;
    let unknown_id = Uuid::new_v4(); // never inserted

    let repo = SystemRepository::new(pool.clone());
    let returned = repo
        .list_active_agent_ids(&[active_id, revoked_id, unknown_id])
        .await
        .expect("list_active_agent_ids");

    // The active agent is kept (its cached token stays valid).
    assert!(
        returned.contains(&active_id),
        "active agent must be returned"
    );
    // The revoked agent is NOT returned → the sweep evicts its cache entry.
    assert!(
        !returned.contains(&revoked_id),
        "REVOKED agent must be excluded (else its token survives cache eviction)"
    );
    // An id with no row is not conjured into the active set.
    assert!(
        !returned.contains(&unknown_id),
        "unknown agent id must be excluded"
    );
    assert_eq!(
        returned.len(),
        1,
        "exactly the one active agent, got {returned:?}"
    );

    // Cleanup — leave the shared DB as we found it.
    let _ = sqlx::query("DELETE FROM mcp_agents WHERE id = ANY($1)")
        .bind(vec![active_id, revoked_id])
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM agent_roles WHERE id = $1")
        .bind(role_id)
        .execute(&pool)
        .await;
}
