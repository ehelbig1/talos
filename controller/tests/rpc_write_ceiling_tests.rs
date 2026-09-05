//! The signed memory-RPC `Set`/`Delete` route must obey the actor's write
//! ceiling — the second controller-side gap in the #750 class.
//!
//! # What this pins, and why a unit test could not
//!
//! `actors.max_write_ceiling` is ONE control. #750 established that it must be
//! checked on EVERY route to a mutation, closed the controller's
//! `__memory_write__` envelope route, and RECORDED the next one without fixing
//! it: the memory-RPC `MemoryOp::Set` handler in `talos-rpc-subscribers`
//! "still TRUSTS the worker's gate".
//!
//! That trust is misplaced for a specific, nameable reason. The request is
//! HMAC-signed under `WORKER_SHARED_KEY`, which is **fleet-shared**: any
//! process holding that key can mint a `Set` naming any actor. A worker
//! booted without `TALOS_WRITE_CEILING_ENFORCED` — the state
//! `get_platform_info.fleet.write_ceiling.enforced_by = "some"` reports and
//! #752 calls "the dangerous one" — refuses nothing locally, and the
//! controller persisted whatever it sent.
//!
//! These tests drive the PRODUCTION entry point: the real
//! `spawn_memory_rpc_subscriber`, over a real NATS connection, with a real
//! signed `MemoryRpcRequest`, against a real Postgres. The assertion is on the
//! DATABASE, not on a helper's return value (#724's lesson: a guard that
//! drives the helper instead of the call site stays green when the call site
//! is rewired).
//!
//! Deliberately written to COMPILE on pristine `main` — no new enum variant is
//! named, no changed signature is called — so it fails there BY ASSERTION
//! (`assert_eq!(rows, 0)` seeing 1), which is evidence, rather than by a
//! compile error, which is not.
//!
//! Runs in CI via `scripts/test-integration.sh` (**CTRL_TESTS**), invoked by
//! quality.yml's `integration` job as `make test-integration`. It uses the
//! `common` harness, so it needs `DATABASE_URL` pointed at a migrated template
//! database — which is what CTRL_TESTS supplies and TC_TESTS does not
//! (sub-leg 64b) — plus `TALOS_TEST_NATS_URL`, which that script exports for
//! both loops.

mod common;

use std::sync::Arc;

use serde_json::json;
use talos_memory::database_rpc::{DatabaseRpcReply, DatabaseRpcRequest, SUBJECT_DATABASE_QUERY};
use talos_memory::integration_state_rpc::{
    IntegrationOp, IntegrationStateReply, IntegrationStateRequest, SUBJECT_INTEGRATION_STATE_OP,
};
use talos_memory::memory_rpc::{MemoryOp, MemoryRpcReply, MemoryRpcRequest, SUBJECT_MEMORY_OP};
use uuid::Uuid;

/// Enforcement is a per-process `OnceLock`, so it must be set before the first
/// read anywhere in this binary. Every phase here wants it ON; the flag-OFF
/// (staged-rollout default) case is covered by the pure unit tests in
/// `talos_rpc_subscribers::write_ceiling`, which take `enforced` as a
/// parameter precisely so it need not be a process global.
fn enforce_write_ceiling() {
    std::env::set_var("TALOS_WRITE_CEILING_ENFORCED", "1");
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    // Keep the write path hermetic: an unconfigured embedding provider makes
    // `generate_embedding` return `None` and the row still lands, which is the
    // behaviour under test. A half-configured provider would add an HTTP
    // timeout to every phase.
    std::env::remove_var("EMBEDDING_API_URL");
}

/// Seed a user, its personal org, and one actor at the given ceiling.
/// Byte-for-byte the shape `write_ceiling_memory_write_tests` uses, so the two
/// binaries cannot drift about what "a readonly actor" is.
async fn seed_actor(pool: &sqlx::Pool<sqlx::Postgres>, ceiling: &str) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("rpcwc-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("rpcwcorg-{tag}"))
    .bind(format!("rpcwcorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, org_id, max_write_ceiling) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor)
    .bind(user)
    .bind(format!("rpcwc-actor-{tag}"))
    .bind(org)
    .bind(ceiling)
    .execute(pool)
    .await
    .expect("seed actor");
    actor
}

/// Register the real memory crypto hook (Phase B: writes have no plaintext
/// fallback, so without this a permitted write fails and the CONTROL case
/// would pass for the wrong reason).
async fn register_crypto(pool: &sqlx::Pool<sqlx::Postgres>) {
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
}

async fn count_memory_rows(pool: &sqlx::Pool<sqlx::Postgres>, actor: Uuid, key: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM actor_memory WHERE actor_id = $1 AND key = $2",
    )
    .bind(actor)
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("count actor_memory")
}

/// Send one signed op to the live subscriber and return the decoded reply.
/// This is the WHOLE production path: sign → NATS → admission gate → handler.
async fn call_rpc(nats: &async_nats::Client, actor: Uuid, op: MemoryOp) -> MemoryRpcReply {
    let req = MemoryRpcRequest::new_signed(actor, op).expect("sign (HMAC key registered)");
    let payload = serde_json::to_vec(&req).expect("serialize request");
    let msg = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        nats.request(SUBJECT_MEMORY_OP, payload.into()),
    )
    .await
    .expect("subscriber replied within 10s")
    .expect("NATS request succeeded");
    serde_json::from_slice(&msg.payload).expect("decode reply")
}

/// The integration-state sibling of [`call_rpc`].
async fn call_integration_rpc(
    nats: &async_nats::Client,
    actor: Uuid,
    user: Uuid,
    op: IntegrationOp,
) -> IntegrationStateReply {
    let req = IntegrationStateRequest::new_signed("rpcwc".into(), actor, user, op)
        .expect("sign integration-state request");
    let payload = serde_json::to_vec(&req).expect("serialize request");
    let msg = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        nats.request(SUBJECT_INTEGRATION_STATE_OP, payload.into()),
    )
    .await
    .expect("subscriber replied within 10s")
    .expect("NATS request succeeded");
    serde_json::from_slice(&msg.payload).expect("decode reply")
}

/// The database sibling of [`call_rpc`].
async fn call_database_rpc(
    nats: &async_nats::Client,
    actor: Uuid,
    sql: String,
    params: Vec<String>,
    is_fetch: bool,
) -> DatabaseRpcReply {
    let req = DatabaseRpcRequest::new_signed(actor, sql, params, is_fetch)
        .expect("sign database request");
    let payload = serde_json::to_vec(&req).expect("serialize request");
    let msg = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        nats.request(SUBJECT_DATABASE_QUERY, payload.into()),
    )
    .await
    .expect("subscriber replied within 20s")
    .expect("NATS request succeeded");
    serde_json::from_slice(&msg.payload).expect("decode reply")
}

async fn count_integration_rows(pool: &sqlx::Pool<sqlx::Postgres>, user: Uuid, key: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM integration_state \
         WHERE integration_name = 'rpcwc' AND user_id = $1 AND key = $2",
    )
    .bind(user)
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("count integration_state")
}

/// ONE test, six phases, ONE database — and the reason is worth stating
/// rather than leaving as an oddity. `talos_memory::register_memory_crypto_hook`
/// is a process-wide `OnceLock` (first registration wins), so parallel
/// `#[tokio::test]`s on separate isolated databases would all encrypt through
/// whichever pool registered first and the others' writes would fail. That is
/// the worst possible arrangement here: the CONTROL would fail while the
/// negative assertion went green for the wrong reason.
///
/// # Phase 1 — the regression
///
/// A `readonly` actor's `Set`. On pristine `main` this FAILS at the row
/// assertion: the write lands and the reply says `Ok`.
///
/// # Phase 2 — the control
///
/// Same subscriber, same enforcement, same op; only the ceiling differs. A
/// "fix" that broke memory-RPC writes for EVERY actor would pass phase 1.
///
/// # Phase 3 — Delete is a mutation too
///
/// `agent-memory-delete` is a separately ceiling-gated op in the worker. A
/// gate applied to `Set` alone would leave a `readonly` actor able to destroy
/// its own memory.
///
/// # Phase 4 — reads are unaffected
///
/// The ceiling bounds MUTATION, not recall. A gate that also refused `Get`
/// would be a different, larger change than the one this is.
///
/// # Phases 5 and 6 — the sibling protocols
///
/// `integration-state-set` and a mutating `database-query` are the other
/// ceiling-gated worker ops the CONTROLLER performs. Phase 6 includes the
/// data-modifying-CTE shape, which parses as `Statement::Query` and which the
/// first version of the controller's classifier called a read.
#[tokio::test]
async fn write_ceiling_gates_every_controller_served_rpc_mutation() {
    enforce_write_ceiling();

    // Fleet-shared HMAC key: the same value signs (as a worker would) and
    // verifies (as the controller does), in one process. That symmetry IS the
    // threat model — see the module docs.
    talos_memory::rpc_auth::register_hmac_key(Arc::new(b"rpc-write-ceiling-test-key".to_vec()));

    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;

    let nats_url = std::env::var("TALOS_TEST_NATS_URL")
        .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let nats = async_nats::connect(&nats_url)
        .await
        .unwrap_or_else(|e| panic!("connect to NATS at {nats_url}: {e}"));

    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    talos_rpc_subscribers::spawn_memory_rpc_subscriber(
        Arc::new(nats.clone()),
        pool.clone(),
        shutdown_rx,
    );
    // Let the subscription bind before the first request; `nats.request` has
    // no delivery guarantee to a subject nobody is listening on yet.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // ── Phase 1: readonly actor → REFUSED ────────────────────────────────
    let ro_actor = seed_actor(&pool, "readonly").await;
    let ro_key = format!("rpcprobe/{}", Uuid::new_v4());
    let reply = call_rpc(
        &nats,
        ro_actor,
        MemoryOp::Set {
            key: ro_key.clone(),
            value: json!({"note": "the worker believes it wrote this"}),
            memory_type: "episodic".into(),
            ttl_hours: Some(1.0),
            metadata: None,
        },
    )
    .await;
    // The DATABASE assertion comes first on purpose: it is the load-bearing
    // claim. A refusal reply over a write that landed anyway would be worse
    // than no gate at all.
    assert_eq!(
        count_memory_rows(&pool, ro_actor, &ro_key).await,
        0,
        "a readonly actor's memory-RPC Set must not reach actor_memory"
    );
    assert!(
        reply.result.is_err(),
        "a readonly actor's memory-RPC Set must be refused, got {:?}",
        reply.result
    );

    // ── Phase 2: write actor → PERMITTED (the control) ───────────────────
    let rw_actor = seed_actor(&pool, "write").await;
    let rw_key = format!("rpcprobe/{}", Uuid::new_v4());
    let reply = call_rpc(
        &nats,
        rw_actor,
        MemoryOp::Set {
            key: rw_key.clone(),
            value: json!({"note": "permitted"}),
            memory_type: "episodic".into(),
            ttl_hours: Some(1.0),
            metadata: None,
        },
    )
    .await;
    assert!(
        reply.result.is_ok(),
        "a write-ceiling actor's memory-RPC Set must still succeed, got {:?}",
        reply.result
    );
    assert_eq!(
        count_memory_rows(&pool, rw_actor, &rw_key).await,
        1,
        "the control write must land — otherwise phase 1 proves nothing"
    );

    // ── Phase 3: Delete is a mutation too ────────────────────────────────
    // Seed a row for the readonly actor through the PLATFORM path (an
    // operator's `actor_remember` write, which the ceiling does not speak to),
    // then try to destroy it over the RPC the ceiling DOES speak to.
    let del_key = format!("rpcprobe/{}", Uuid::new_v4());
    talos_memory::persist_memory_with_metadata(
        &pool,
        ro_actor,
        &del_key,
        &json!({"seeded": "by the operator"}),
        None,
        "episodic",
        Some(1.0),
    )
    .await
    .expect("operator seed write");
    assert_eq!(
        count_memory_rows(&pool, ro_actor, &del_key).await,
        1,
        "seed must exist before the delete probe"
    );
    let reply = call_rpc(
        &nats,
        ro_actor,
        MemoryOp::Delete {
            key: del_key.clone(),
        },
    )
    .await;
    assert_eq!(
        count_memory_rows(&pool, ro_actor, &del_key).await,
        1,
        "a readonly actor's memory-RPC Delete must not remove the row"
    );
    assert!(
        reply.result.is_err(),
        "a readonly actor's memory-RPC Delete must be refused, got {:?}",
        reply.result
    );

    // ── Phase 4: reads are unaffected ────────────────────────────────────
    let reply = call_rpc(
        &nats,
        ro_actor,
        MemoryOp::Get {
            key: del_key.clone(),
        },
    )
    .await;
    assert!(
        reply.result.is_ok(),
        "the ceiling bounds mutation, not recall — Get must still succeed for \
         a readonly actor, got {:?}",
        reply.result
    );

    // ── Phase 5: the SIBLING protocols ───────────────────────────────────
    // `integration-state-set` / `-delete` and a mutating `database-query` are
    // the other ceiling-gated worker ops the CONTROLLER performs. Gating only
    // memory would repeat #750's own recorded lesson ("one of three protocols
    // fixed") one change later.
    let (_tx2, shutdown_rx2) = tokio::sync::watch::channel(false);
    talos_rpc_subscribers::spawn_integration_state_subscriber(
        Arc::new(nats.clone()),
        pool.clone(),
        shutdown_rx2,
    );
    let (_tx3, shutdown_rx3) = tokio::sync::watch::channel(false);
    talos_rpc_subscribers::spawn_database_rpc_subscriber(
        Arc::new(nats.clone()),
        pool.clone(),
        shutdown_rx3,
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let ro_user: Uuid = sqlx::query_scalar("SELECT user_id FROM actors WHERE id = $1")
        .bind(ro_actor)
        .fetch_one(&pool)
        .await
        .expect("read actor owner");
    let rw_user: Uuid = sqlx::query_scalar("SELECT user_id FROM actors WHERE id = $1")
        .bind(rw_actor)
        .fetch_one(&pool)
        .await
        .expect("read actor owner");

    // integration-state: refused for readonly, permitted for write.
    let is_key = format!("rpcprobe-{}", Uuid::new_v4().simple());
    let reply = call_integration_rpc(
        &nats,
        ro_actor,
        ro_user,
        IntegrationOp::Set {
            key: is_key.clone(),
            value: json!({"cursor": "the worker believes it wrote this"}),
            ttl_seconds: None,
            slots: Default::default(),
        },
    )
    .await;
    assert_eq!(
        count_integration_rows(&pool, ro_user, &is_key).await,
        0,
        "a readonly actor's integration-state Set must not reach integration_state"
    );
    assert!(
        reply.result.is_err(),
        "a readonly actor's integration-state Set must be refused, got {:?}",
        reply.result
    );

    let rw_key = format!("rpcprobe-{}", Uuid::new_v4().simple());
    let reply = call_integration_rpc(
        &nats,
        rw_actor,
        rw_user,
        IntegrationOp::Set {
            key: rw_key.clone(),
            value: json!({"cursor": "permitted"}),
            ttl_seconds: None,
            slots: Default::default(),
        },
    )
    .await;
    assert!(
        reply.result.is_ok(),
        "a write-ceiling actor's integration-state Set must still succeed, got {:?}",
        reply.result
    );
    assert_eq!(
        count_integration_rows(&pool, rw_user, &rw_key).await,
        1,
        "the integration-state control write must land"
    );

    // ── Phase 6: database DML vs SELECT ──────────────────────────────────
    // A `readonly` actor may still SELECT. It may not INSERT — including via
    // a data-modifying CTE, the shape that parses as `Statement::Query` and
    // which the FIRST version of the controller's classifier called a read.
    //
    // The probe writes to a scratch table, and every assertion is on the
    // TABLE, never on `result.is_err()`. That is not fussiness: the first
    // version of this phase asserted `is_err()` against an INSERT into
    // `actor_memory`, which fails its NOT NULL constraints anyway — so
    // removing the gate entirely left the phase GREEN. It was the only one of
    // four mutations that survived, and it survived by being satisfied for
    // the wrong reason.
    sqlx::query("CREATE TABLE rpcwc_probe (a int)")
        .execute(&pool)
        .await
        .expect("create scratch probe table");
    let probe_rows = |pool: sqlx::Pool<sqlx::Postgres>| async move {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM rpcwc_probe")
            .fetch_one(&pool)
            .await
            .expect("count probe rows")
    };

    let reply = call_database_rpc(&nats, ro_actor, "SELECT 1 AS n".into(), vec![], true).await;
    assert!(
        reply.result.is_ok(),
        "a readonly actor's SELECT must still run, got {:?}",
        reply.result
    );

    for (sql, why) in [
        ("INSERT INTO rpcwc_probe (a) VALUES (1)", "plain INSERT"),
        (
            "WITH ins AS (INSERT INTO rpcwc_probe (a) VALUES (2) RETURNING a) \
             SELECT * FROM ins",
            "INSERT hiding in a data-modifying CTE",
        ),
    ] {
        let reply = call_database_rpc(&nats, ro_actor, sql.to_string(), vec![], false).await;
        assert_eq!(
            probe_rows(pool.clone()).await,
            0,
            "a readonly actor's mutating query must not reach the database ({why})"
        );
        assert!(
            reply.result.is_err(),
            "a readonly actor's mutating query must be refused ({why}), got {:?}",
            reply.result
        );
    }

    // The control: the SAME statement, for a write-ceiling actor, must land.
    // Without it, a gate that refused every DML would pass everything above.
    let reply = call_database_rpc(
        &nats,
        rw_actor,
        "INSERT INTO rpcwc_probe (a) VALUES (3)".into(),
        vec![],
        false,
    )
    .await;
    assert!(
        reply.result.is_ok(),
        "a write-ceiling actor's mutating query must still run, got {:?}",
        reply.result
    );
    assert_eq!(
        probe_rows(pool.clone()).await,
        1,
        "the database control write must land — otherwise the refusals above \
         prove nothing"
    );
}
