//! `session_start`'s `active_actors` lists ACTIVE actors only, and inactive
//! actors cannot crowd them out of its limit (2026-09-30).
//!
//! The read used `status != 'archived'`, so a terminated probe actor was
//! reported under `active_actors` — and, because the `LIMIT` applied after
//! that filter, enough suspended or terminated actors newer than an active
//! one would push the active one out of the list entirely. This drives the
//! PRODUCTION reads against a real clone.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use talos_advanced_repository::AdvancedRepository;
use uuid::Uuid;

#[tokio::test]
async fn inactive_actors_neither_appear_as_active_nor_consume_the_limit() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'actors')",
    )
    .bind(user)
    .bind(format!("actor-listing-{user}@example.com"))
    .execute(&pool)
    .await
    .expect("seed user");
    let actor = |name: String, status: &'static str, age_mins: i32| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO actors (id, user_id, name, status, created_at) \
                 VALUES ($1, $2, $3, $4, NOW() - make_interval(mins => $5::int))",
            )
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(name)
            .bind(status)
            .bind(age_mins)
            .execute(&pool)
            .await
            .expect("seed actor");
        }
    };
    // The one active actor is the OLDEST row; 25 newer terminated actors and
    // 2 suspended ones sort ahead of it under `created_at DESC`.
    actor("the-active-one".into(), "active", 1_000).await;
    for i in 0..25 {
        actor(format!("terminated-{i}"), "terminated", i).await;
    }
    actor("paused-a".into(), "suspended", 30).await;
    actor("paused-b".into(), "suspended", 31).await;
    actor("retired".into(), "archived", 32).await;

    let repo = AdvancedRepository::new(pool.clone());
    let active = repo
        .list_active_actors_with_memory_count(user, 20)
        .await
        .expect("active read");
    let names: Vec<&str> = active.iter().map(|r| r.name.as_str()).collect();
    // The migration may also give the user a Default actor; every row must be
    // active, and the old active actor must not have been pushed out.
    assert!(names.contains(&"the-active-one"), "crowded out: {names:?}");
    assert!(active.iter().all(|r| r.status == "active"), "{names:?}");

    let mut counts = repo.count_actors_by_status(user).await.expect("counts");
    counts.sort();
    let get = |s: &str| counts.iter().find(|(k, _)| k == s).map_or(0, |(_, n)| *n);
    assert_eq!(get("terminated"), 25);
    assert_eq!(get("suspended"), 2);
    assert_eq!(get("archived"), 1);
}
