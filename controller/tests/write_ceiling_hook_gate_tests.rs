//! `ControllerNodeHook`'s OWN write-ceiling gate — the defence-in-depth half
//! of #750, and the only gate on the path with no engine in the loop.
//!
//! # Why this is a SEPARATE binary from `write_ceiling_memory_write_tests`
//!
//! Two reasons, both measured rather than assumed.
//!
//! 1. **`write_ceiling_memory_write_tests` cannot cover this.** That binary
//!    drives the engine, and the engine strips a refused `__memory_write__`
//!    envelope BEFORE the lifecycle hook ever sees it — so the hook's own
//!    check is unreachable there by construction. Mutation-proved: neutering
//!    the hook's gate (`if false`) while leaving the engine's intact leaves
//!    that binary GREEN. Its failure direction is silent, which is exactly the
//!    kind of survivor worth a second test rather than a footnote.
//!    `handle_test_module` calls `persist_memory_write_if_present` DIRECTLY,
//!    with no engine, so on that path this gate is the only one there is.
//! 2. **`talos_memory::register_memory_crypto_hook` is a process-wide
//!    `OnceLock`** (first registration wins). Two test binaries are two
//!    processes; two `#[tokio::test]`s in one process would fight over it and
//!    the loser would encrypt against a DEK that does not exist in its own
//!    isolated database. That is not hypothetical — it is how the first draft
//!    of the sibling binary failed.
//!
//! Unlike the sibling, this file does NOT compile on pristine `main`: the
//! ceiling is a new required parameter, which is the point — on main the
//! method had no way to be told. The behavioural regression proof lives in the
//! sibling binary, which does compile there and fails by assertion.
//!
//! CI: `scripts/test-integration.sh` **CTRL_TESTS** (`common` harness ⇒ needs
//! `DATABASE_URL`, sub-leg 64b).

mod common;

use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

fn enforce_write_ceiling() {
    std::env::set_var("TALOS_WRITE_CEILING_ENFORCED", "1");
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

async fn seed_actor(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("wch-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("wchorg-{tag}"))
    .bind(format!("wchorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("wch-actor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");
    actor
}

async fn count_rows(pool: &sqlx::Pool<sqlx::Postgres>, actor: Uuid, key: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM actor_memory WHERE actor_id = $1 AND key = $2",
    )
    .bind(actor)
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("count actor_memory")
}

/// Call the hook the way `handle_test_module` does — directly, no engine — at
/// each ceiling, and assert the database.
#[tokio::test]
async fn hook_refuses_a_readonly_envelope_with_no_engine_in_the_loop() {
    enforce_write_ceiling();
    let (pool, _db) = common::isolated_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));

    let actor = seed_actor(&pool).await;
    let hook = talos_engine::node_hook::ControllerNodeHook::new(pool.clone());

    // Refused: readonly ceiling.
    let refused_key = format!("hookgate-ro/{}", Uuid::new_v4());
    hook.persist_memory_write_if_present(
        Some(actor),
        &json!({
            "__memory_write__": {
                "key": refused_key,
                "memory_type": "scratchpad",
                "value": {"note": "must not land"}
            }
        }),
        talos_workflow_engine_core::WriteCeiling::ReadOnly,
    );

    // Permitted: same actor, same hook, same envelope shape — only the ceiling
    // differs. Without this control a hook that refused EVERYTHING would pass.
    let allowed_key = format!("hookgate-rw/{}", Uuid::new_v4());
    hook.persist_memory_write_if_present(
        Some(actor),
        &json!({
            "__memory_write__": {
                "key": allowed_key,
                "memory_type": "scratchpad",
                "value": {"note": "must land"}
            }
        }),
        talos_workflow_engine_core::WriteCeiling::Write,
    );

    // The persist is `tokio::spawn`ed. Wait for the PERMITTED one to appear —
    // that is the signal the spawned work has run, which makes the refused
    // one's absence meaningful rather than a race we won.
    let mut landed = 0;
    for _ in 0..100 {
        landed = count_rows(&pool, actor, &allowed_key).await;
        if landed > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        landed, 1,
        "the write-ceiling envelope must still persist through the hook"
    );
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        count_rows(&pool, actor, &refused_key).await,
        0,
        "the hook must refuse a readonly actor's envelope even with no engine \
         to strip it first — this is the only gate on the test_module path"
    );
}
