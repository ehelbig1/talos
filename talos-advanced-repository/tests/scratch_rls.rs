//! RFC 0004 M4 — end-to-end proof that `scratch_sessions` is RLS-enforced
//! through the real `AdvancedRepository` methods, under a NON-superuser
//! role (the production condition; a superuser would bypass RLS).
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (a SUPERUSER url — the test creates
//! a non-superuser role + grants). Skips when unset.
//! ```sh
//! export TALOS_TEST_DATABASE_URL="postgres://postgres:talos@localhost:5433/talos"
//! cargo test -p talos-advanced-repository --test scratch_rls -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, Pool, Postgres};
use talos_advanced_repository::AdvancedRepository;
use talos_db::begin_tenant_read_scoped;
use talos_tenancy::TenantReadScope;
use uuid::Uuid;

const ROLE: &str = "talos_scratch_rls_app";
const PW: &str = "scratch_rls_pw";

fn su_url() -> Option<String> {
    match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL (superuser) to run scratch_rls");
            None
        }
    }
}

async fn connect(url: &str, max: u32) -> Pool<Postgres> {
    PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect")
}

#[tokio::test]
async fn scratch_sessions_rls_isolates_users_through_the_repository() {
    let Some(su_url) = su_url() else { return };
    let su = connect(&su_url, 2).await;
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();

    // Setup: non-superuser role, two users, grants.
    su.execute(
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{ROLE}') THEN \
               CREATE ROLE {ROLE} LOGIN PASSWORD '{PW}'; END IF; END $$;"
        )
        .as_str(),
    )
    .await
    .expect("create role");
    for (u, label) in [(user_a, "a"), (user_b, "b")] {
        sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x',$3)")
            .bind(u)
            .bind(format!("scratch-{label}-{}@test.invalid", u.simple()))
            .bind(label)
            .execute(&su)
            .await
            .expect("insert user");
    }
    su.execute(
        format!("GRANT SELECT, INSERT, UPDATE, DELETE ON scratch_sessions TO {ROLE};").as_str(),
    )
    .await
    .expect("grant");

    // The repository, bound to a pool connecting as the NON-superuser role.
    let after_at = su_url.rsplit_once('@').map(|(_, r)| r).unwrap_or(&su_url);
    let app_pool = connect(&format!("postgres://{ROLE}:{PW}@{after_at}"), 4).await;
    let repo = AdvancedRepository::new(app_pool.clone());

    // User A creates a scratch session and can read/list it.
    repo.upsert_scratch_session(user_a, "s1", "let x = 1;", "minimal-node")
        .await
        .expect("A upsert");
    assert!(
        repo.get_scratch_session(user_a, "s1").await.expect("A get").is_some(),
        "A must see its own session"
    );
    assert_eq!(repo.list_scratch_sessions(user_a).await.expect("A list").len(), 1);

    // User B (same repo, same pooled non-superuser role) CANNOT see A's
    // session — defense in depth (app-layer WHERE + RLS).
    assert!(
        repo.get_scratch_session(user_b, "s1").await.expect("B get").is_none(),
        "B must NOT see A's session"
    );
    assert_eq!(repo.list_scratch_sessions(user_b).await.expect("B list").len(), 0);
    // B's delete of A's session affects zero rows.
    assert_eq!(repo.delete_scratch_session(user_b, "s1").await.expect("B delete"), 0);

    // RLS-SPECIFIC proof: a raw `SELECT` with NO app-layer WHERE, run on a
    // tenant-scoped tx, sees only the scoping user's rows. This isolates
    // via RLS alone (not the methods' WHERE clause).
    let mut tx_b = begin_tenant_read_scoped(&app_pool, &TenantReadScope::new(user_b, vec![]))
        .await
        .unwrap();
    let b_visible: i64 = sqlx::query_scalar("SELECT count(*) FROM scratch_sessions")
        .fetch_one(&mut *tx_b)
        .await
        .unwrap();
    tx_b.commit().await.unwrap();
    assert_eq!(b_visible, 0, "RLS must hide A's row from B even with no WHERE clause");

    let mut tx_a = begin_tenant_read_scoped(&app_pool, &TenantReadScope::new(user_a, vec![]))
        .await
        .unwrap();
    let a_visible: i64 = sqlx::query_scalar("SELECT count(*) FROM scratch_sessions")
        .fetch_one(&mut *tx_a)
        .await
        .unwrap();
    tx_a.commit().await.unwrap();
    assert_eq!(a_visible, 1, "RLS must show A its own row");

    // Cleanup.
    let _ = su.execute("DELETE FROM scratch_sessions WHERE name = 's1';").await;
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(u).execute(&su).await;
    }
    let _ = su.execute(format!("DROP ROLE IF EXISTS {ROLE};").as_str()).await;
}
