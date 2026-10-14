//! A rehearsal can read an actor's memory without changing it (2026-10-14).
//!
//! `test_module(actor_id)` scoped a rehearsal's memory calls to that actor,
//! writes included; without `actor_id` it read nothing. So a keeper module
//! (one that reads `work/kinds` with `agent_memory::get_entry`) could be seen
//! working on real state only by letting it change that state.
//!
//! These drive the PRODUCTION memory path: a `TalosContext` built as a job
//! builds one, its `agent_memory` host functions, the signed memory RPC over a
//! real NATS connection, the real `spawn_memory_rpc_subscriber`, and a real
//! Postgres. Assertions are on the database. The rehearsal value is the one
//! `test_module` puts on that context (`SecurityPolicy::memory_rehearsal`).
//!
//! Row security is left OFF in this binary (`TALOS_RLS_SET_ROLE=0`): the
//! ownership test proves the handler's own check.
//!
//! Needs `TALOS_TEST_NATS_URL` (the integration job exports it) and the
//! migrated template (`common` harness).

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::collections::HashMap;
use std::sync::Arc;

use mcp_common::{agent, error_message, mcp_state};
use serde_json::json;
use talos_worker_runtime::bindings::talos::core::agent_memory::{self as wit_agent_memory, Host};
use talos_worker_runtime::context::TalosContext;
use talos_worker_runtime::expose_fallback::ExposeFallback;
use talos_worker_runtime::memory_rehearsal::MemoryRehearsal;
use talos_worker_runtime::wit_inspector::CapabilityWorld;
use talos_workflow_job_protocol::LlmTier;
use uuid::Uuid;

fn hermetic() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "0");
    // Read once per process by the worker runtime, so it is set before any
    // write: the ceiling scenario needs it on, and the actor here is seeded
    // with a `write` ceiling, so nothing else is refused by it.
    std::env::set_var("TALOS_WRITE_CEILING_ENFORCED", "1");
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    std::env::remove_var("EMBEDDING_API_URL");
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("memreh-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

async fn seed_actor(pool: &sqlx::PgPool, user: Uuid) -> Uuid {
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("memreh-{tag}"))
    .bind(format!("memreh-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    // `write`, stated: the column's default is `readonly`.
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, org_id, max_write_ceiling) \
         VALUES ($1, $2, $3, $4, 'write')",
    )
    .bind(actor)
    .bind(user)
    .bind(format!("memreh-actor-{tag}"))
    .bind(org)
    .execute(pool)
    .await
    .expect("seed actor");
    actor
}

async fn register_crypto(pool: &sqlx::PgPool) {
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
}

async fn rows(pool: &sqlx::PgPool, actor: Uuid, key: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM actor_memory WHERE actor_id = $1 AND key = $2",
    )
    .bind(actor)
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("count actor_memory")
}

struct World {
    pool: sqlx::PgPool,
    _db: common::TestDb,
    nats: async_nats::Client,
    actor: Uuid,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

/// A migrated database, the production memory subscriber on a real NATS, and
/// an actor holding `work/kinds`.
async fn world() -> World {
    hermetic();
    talos_memory::rpc_auth::register_hmac_key(Arc::new(b"memory-rehearsal-test-key".to_vec()));
    let (pool, db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;
    let nats_url = std::env::var("TALOS_TEST_NATS_URL")
        .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let nats = async_nats::connect(&nats_url)
        .await
        .unwrap_or_else(|e| panic!("connect to NATS at {nats_url}: {e}"));
    let (tx, shutdown_rx) = tokio::sync::watch::channel(false);
    talos_rpc_subscribers::spawn_memory_rpc_subscriber(
        Arc::new(nats.clone()),
        pool.clone(),
        shutdown_rx,
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    talos_memory::persist_memory(
        &pool,
        actor,
        "work/kinds",
        &json!({ "kinds": ["made-up-kind"] }),
        "semantic",
        None,
    )
    .await
    .expect("seed work/kinds");
    World {
        pool,
        _db: db,
        nats,
        actor,
        _shutdown: tx,
    }
}

/// ONE test function, the scenarios in turn on one world: the memory crypto
/// hook and the HMAC key are process-wide, registered once against one
/// database (the shape `rpc_write_ceiling_tests` uses for the same reason).
#[tokio::test]
async fn a_rehearsal_reads_an_actors_memory_and_can_leave_it_unchanged() {
    let w = world().await;
    a_discarding_rehearsal_reads_the_actors_key_and_changes_nothing(&w).await;
    an_applying_rehearsal_writes_as_before(&w).await;
    without_an_actor_nothing_is_read(&w).await;
    a_stranger_cannot_rehearse_against_another_users_actor(&w).await;
    an_unknown_memory_writes_value_is_refused(&w).await;
    a_discarding_rehearsal_still_obeys_the_write_ceiling(&w).await;
}

/// A context built as a job builds one, scoped to `actor`, carrying the
/// rehearsal `test_module` would put on it.
fn context(
    w: &World,
    actor: Option<Uuid>,
    rehearsal: Option<Arc<MemoryRehearsal>>,
) -> TalosContext {
    let mut ctx = TalosContext::new(
        CapabilityWorld::Agent,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        Some(Arc::new(w.nats.clone())),
        false,
        None,
        Arc::new(ExposeFallback::new()),
        LlmTier::default(),
        None,
    )
    .expect("context builds");
    ctx.actor_id = actor;
    // `test_module` stamps the actor's own ceiling; the seeded actor's is
    // write.
    ctx.max_write_ceiling = talos_workflow_job_protocol::WriteCeiling::Write;
    ctx.memory_rehearsal = rehearsal;
    ctx
}

/// `memory_writes: "discard"`: the keeper reads the actor's key, and its
/// writes and deletes are answered `Ok` and change nothing. The report names
/// the keys, never a value.
///
/// MUTATION that turns it red: drop the `if r.discards_writes() { return
/// Ok(()) }` in the host `set` (or `delete`).
async fn a_discarding_rehearsal_reads_the_actors_key_and_changes_nothing(w: &World) {
    let rehearsal = Arc::new(MemoryRehearsal::new(true));
    let mut ctx = context(w, Some(w.actor), Some(rehearsal.clone()));

    let entry = ctx
        .get_entry("work/kinds".to_string())
        .await
        .expect("get_entry")
        .expect("the actor holds work/kinds");
    assert!(entry.value.contains("made-up-kind"), "{}", entry.value);
    ctx.set("work/log/new".to_string(), "{\"n\":1}".to_string())
        .await
        .expect("a discarded set answers Ok");
    ctx.delete("work/kinds".to_string())
        .await
        .expect("a discarded delete answers Ok");
    let keys = ctx
        .list_keys(Some("work/".to_string()))
        .await
        .expect("list_keys");
    assert!(keys.contains(&"work/kinds".to_string()), "{keys:?}");

    assert_eq!(
        rows(&w.pool, w.actor, "work/log/new").await,
        0,
        "the set was applied"
    );
    assert_eq!(
        rows(&w.pool, w.actor, "work/kinds").await,
        1,
        "the delete was applied"
    );

    let report = rehearsal.report();
    assert_eq!(report["writes_applied"], false);
    assert_eq!(report["keys_read"], json!(["work/kinds"]));
    assert_eq!(report["prefixes_listed"], json!(["work/"]));
    assert_eq!(
        report["writes"],
        json!([
            { "op": "set", "key": "work/log/new" },
            { "op": "delete", "key": "work/kinds" }
        ])
    );
    assert!(
        !report.to_string().contains("made-up-kind"),
        "a value reached the report"
    );
}

/// `memory_writes: "apply"` (the default, and what an actor-scoped rehearsal
/// has always done): the write lands, and the report says it was applied.
async fn an_applying_rehearsal_writes_as_before(w: &World) {
    let rehearsal = Arc::new(MemoryRehearsal::new(false));
    let mut ctx = context(w, Some(w.actor), Some(rehearsal.clone()));
    ctx.set("work/log/new".to_string(), "{\"n\":1}".to_string())
        .await
        .expect("set");
    assert_eq!(rows(&w.pool, w.actor, "work/log/new").await, 1);
    assert_eq!(rehearsal.report()["writes_applied"], true);
}

/// Discarding does not skip the gates that decide whether a write MAY be
/// made: a readonly actor's write is still refused, not answered `Ok`.
async fn a_discarding_rehearsal_still_obeys_the_write_ceiling(w: &World) {
    let rehearsal = Arc::new(MemoryRehearsal::new(true));
    let mut ctx = context(w, Some(w.actor), Some(rehearsal));
    ctx.max_write_ceiling = talos_workflow_job_protocol::WriteCeiling::ReadOnly;
    let refused = ctx.set("work/log/new".to_string(), "{}".to_string()).await;
    assert!(
        matches!(refused, Err(wit_agent_memory::Error::NotAvailable)),
        "{refused:?}"
    );
}

/// Without an actor, a rehearsal reads nothing, as before.
async fn without_an_actor_nothing_is_read(w: &World) {
    let mut ctx = context(w, None, None);
    assert!(ctx.get_entry("work/kinds".to_string()).await.is_err());
}

/// `test_module` with another user's actor gets the answer a nonexistent
/// actor gets (the actor id the caller sent aside), before any module is
/// loaded or anything runs.
///
/// MUTATION that turns it red: treat every actor as owned in
/// `handle_test_module` (`let owned = true;`).
async fn a_stranger_cannot_rehearse_against_another_users_actor(w: &World) {
    let stranger = seed_user(&w.pool).await;
    let state = mcp_state(w.pool.clone()).await;
    let call = |actor: Uuid| {
        let state = &state;
        async move {
            controller::mcp::sandbox::dispatch(
                "test_module",
                Some(json!(1)),
                &json!({
                    "module_id": Uuid::new_v4().to_string(),
                    "actor_id": actor.to_string(),
                    "memory_writes": "discard",
                }),
                state,
                agent(stranger),
            )
            .await
            .expect("test_module is dispatched")
        }
    };
    let nowhere = Uuid::new_v4();
    let theirs = error_message(&call(w.actor).await).replace(&w.actor.to_string(), "<id>");
    let absent = error_message(&call(nowhere).await).replace(&nowhere.to_string(), "<id>");
    assert_eq!(theirs, absent);
    assert!(theirs.contains("not found or not owned"), "{theirs}");
}

/// An unknown `memory_writes` value is refused, not read as one of the two.
async fn an_unknown_memory_writes_value_is_refused(w: &World) {
    let owner: Uuid = sqlx::query_scalar("SELECT user_id FROM actors WHERE id = $1")
        .bind(w.actor)
        .fetch_one(&w.pool)
        .await
        .unwrap();
    let state = mcp_state(w.pool.clone()).await;
    let resp = controller::mcp::sandbox::dispatch(
        "test_module",
        Some(json!(1)),
        &json!({
            "module_id": Uuid::new_v4().to_string(),
            "actor_id": w.actor.to_string(),
            "memory_writes": "maybe",
        }),
        &state,
        agent(owner),
    )
    .await
    .expect("dispatched");
    assert!(error_message(&resp).contains("memory_writes"), "{resp:?}");
}
