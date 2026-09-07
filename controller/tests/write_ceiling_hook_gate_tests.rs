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

// ── The SCOPE of the ceiling: what it deliberately does NOT gate ─────────────

/// Seed an actor whose `max_write_ceiling` is really `readonly` in the
/// database — the memory tests above pass the ceiling as a parameter and never
/// need the column, but the point of the test below is that a future gate
/// which READS the column must fail loudly, so the column has to be right.
async fn seed_readonly_actor(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    let actor = seed_actor(pool).await;
    sqlx::query("UPDATE actors SET max_write_ceiling = 'readonly' WHERE id = $1")
        .bind(actor)
        .execute(pool)
        .await
        .expect("set readonly ceiling");
    let ceiling: String = sqlx::query_scalar("SELECT max_write_ceiling FROM actors WHERE id = $1")
        .bind(actor)
        .fetch_one(pool)
        .await
        .expect("read back ceiling");
    assert_eq!(ceiling, "readonly", "the fixture must really be readonly");
    actor
}

/// **POSITIVE CONTROL for a decision, not a guard against a bug.**
///
/// #750 found that three output protocols travel ONE node-completion hook on
/// ONE actor binding, gated exactly one of them, and left the other two as "an
/// operator policy call". Decided 2026-09-06 (#768): `actors.max_write_ceiling`
/// governs the ACTOR's own DATA PLANE — actor_memory, integration state,
/// sandbox SQL. `__ops_alert__` and `__ml_distill__` are PLATFORM ingestion
/// that takes the actor id for TENANCY, not because the rows are the actor's
/// data.
///
/// So this test asserts the row LANDS: a `readonly` actor, with
/// `TALOS_WRITE_CEILING_ENFORCED=1` already set by the test above (and by
/// `enforce_write_ceiling()` here), emitting `__ops_alert__` through the real
/// `ControllerNodeHook`, must still write to `ops_alerts`. A future change that
/// "closes the gap" by gating this protocol turns the test red instead of
/// silently taking the one live readonly actor's alert pipeline off the air.
///
/// The refusal that DOES stay is a different rule and is covered below: an
/// envelope with no actor at all has no tenancy principal and is dropped.
///
/// `__ml_distill__` gets no equivalent here, and the reason is measured rather
/// than asserted: `talos_ml::spawn_distill_from_output` short-circuits on the
/// process-global `DISTILL_CONTEXT` `OnceLock` — settable once per test BINARY,
/// which sibling tests in the same process race (the objection check 82 already
/// records about `controller_write_ceiling_enforced`) — and past it the flow
/// needs an ML content-MAC key, an embedding provider, a model and a dataset.
/// The decision for it is pinned in `talos-engine/src/node_hook.rs` at the call
/// site and in `talos_security_audit::UNGATED_OUTPUT_PROTOCOLS`, which names
/// both protocols and is what the operator-facing report renders.
#[tokio::test]
async fn a_readonly_actors_ops_alert_still_lands_because_it_is_outside_the_ceiling() {
    enforce_write_ceiling();
    let (pool, _db) = common::isolated_db_pool().await;
    let actor = seed_readonly_actor(&pool).await;
    let hook = talos_engine::node_hook::ControllerNodeHook::new(pool.clone());

    let dedup = format!("hookgate-opsalert/{}", Uuid::new_v4());
    hook.persist_ops_alert_if_present(
        Some(actor),
        &json!({
            "__ops_alert__": {
                "dedup_key": dedup,
                "source": "hook-gate-test",
                "title": "a readonly actor's diagnostic",
                "severity_hint": "warning"
            }
        }),
    );

    // The ingest is `tokio::spawn`ed behind a tenancy lookup, so poll.
    let mut landed = 0;
    for _ in 0..100 {
        landed =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ops_alerts WHERE dedup_key = $1")
                .bind(&dedup)
                .fetch_one(&pool)
                .await
                .expect("count ops_alerts");
        if landed > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        landed, 1,
        "__ops_alert__ is OUTSIDE the write ceiling by decision (#768): a readonly \
         actor's platform diagnostic must still land. If this failed because someone \
         gated it, read the decision at the call site in talos-engine/src/node_hook.rs \
         before changing this test."
    );

    // The rule that DOES survive: no actor is no tenancy principal. This is
    // the control — without it, a hook that dropped every envelope would pass
    // the assertion above only by accident of ordering.
    let orphan = format!("hookgate-opsalert-orphan/{}", Uuid::new_v4());
    hook.persist_ops_alert_if_present(
        None,
        &json!({
            "__ops_alert__": {
                "dedup_key": orphan,
                "source": "hook-gate-test",
                "title": "no actor bound"
            }
        }),
    );
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ops_alerts WHERE dedup_key = $1")
            .bind(&orphan)
            .fetch_one(&pool)
            .await
            .expect("count orphan ops_alerts"),
        0,
        "an envelope with no actor has no tenancy principal and must be dropped"
    );
}
