//! A `__memory_write__` envelope's TTL, as the database stores it.
//!
//! The envelope reader in `talos_engine::node_hook` defaulted a missing
//! `ttl_hours` to 168 for EVERY memory type, and `talos_memory` honours any
//! explicit TTL, so a `semantic` memory written through the envelope expired a
//! week after its last write — contrary to the envelope's documented
//! "semantic memories ignore TTL". Found live 2026-09-30 on the essay
//! pipeline's covered-titles list.
//!
//! This drives the PRODUCTION chain: a real `ParallelWorkflowEngine`, the real
//! `ControllerNodeHook` bound to a real Postgres pool, and a stub dispatcher
//! standing in only for the worker. The assertions are on
//! `actor_memory.expires_at`, not on a helper's return value.
//!
//! One test, four phases, one database: `talos_memory::register_memory_crypto_hook`
//! is a process-wide `OnceLock` (see `write_ceiling_memory_write_tests`).

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, DispatchJob, DispatchResult,
    NodeDispatcher, WasmModuleArtifact, WriteCeiling,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

/// Stands in for the worker: returns the scripted envelope.
struct EnvelopeDispatcher {
    output: serde_json::Value,
}

#[async_trait]
impl NodeDispatcher for EnvelopeDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult {
            output: self.output.clone(),
        })
    }

    async fn dispatch_chain(
        &self,
        _request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        Err("chain dispatch is not used by this test".into())
    }
}

fn stub_artifact(id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "minimal-node".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

async fn seed_actor(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("ttl-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("ttlorg-{tag}"))
    .bind(format!("ttlorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, org_id, max_write_ceiling) \
         VALUES ($1, $2, $3, $4, 'write')",
    )
    .bind(actor)
    .bind(user)
    .bind(format!("ttl-actor-{tag}"))
    .bind(org)
    .execute(pool)
    .await
    .expect("seed actor");
    actor
}

/// Writes have no plaintext fallback, so the real memory crypto is required.
async fn register_crypto(pool: &sqlx::Pool<sqlx::Postgres>) {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
}

/// Run one node whose output carries `envelope` through the real engine and
/// the real `ControllerNodeHook`.
// disallowed-method: talos_workflow_engine::ParallelWorkflowEngine::set_actor_id — test: binds the actor the envelope is written for
#[allow(clippy::disallowed_methods)]
async fn run_one_node(pool: &sqlx::Pool<sqlx::Postgres>, actor: Uuid, envelope: serde_json::Value) {
    let module = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module(module.to_string(), module, None)
        .build()
        .expect("graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module, stub_artifact(module)),
    ));
    engine.set_actor_id(actor);
    engine.set_max_write_ceiling(WriteCeiling::Write);
    engine.set_node_hook(Arc::new(talos_engine::node_hook::ControllerNodeHook::new(
        pool.clone(),
    )));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    engine
        .run_with_trigger_input_transport(
            Arc::new(EnvelopeDispatcher { output: envelope }),
            None,
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .expect("run succeeds");
}

/// Seconds from now until the row expires, `None` for no expiry. Polls,
/// because the hook persists on a `tokio::spawn`.
async fn expiry_after_write(
    pool: &sqlx::Pool<sqlx::Postgres>,
    actor: Uuid,
    key: &str,
) -> Option<i64> {
    for _ in 0..100 {
        let row: Option<(Option<f64>,)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM expires_at - NOW())::float8 \
             FROM actor_memory WHERE actor_id = $1 AND key = $2",
        )
        .bind(actor)
        .bind(key)
        .fetch_optional(pool)
        .await
        .expect("read actor_memory");
        if let Some((secs,)) = row {
            return secs.map(|s| s.round() as i64);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no actor_memory row for {key} after 5 s");
}

fn envelope(key: &str, memory_type: &str, ttl_hours: Option<f64>) -> serde_json::Value {
    let mut mw = json!({"key": key, "memory_type": memory_type, "value": {"k": key}});
    if let Some(ttl) = ttl_hours {
        mw["ttl_hours"] = json!(ttl);
    }
    json!({ "__memory_write__": mw })
}

fn assert_hours(secs: Option<i64>, hours: i64, what: &str) {
    let secs = secs.unwrap_or_else(|| panic!("{what}: expected an expiry, found none"));
    let want = hours * 3600;
    assert!(
        (secs - want).abs() <= 120,
        "{what}: expected ~{hours} h ({want} s), got {secs} s"
    );
}

#[tokio::test]
async fn the_envelope_ttl_reaches_the_database_as_documented() {
    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;
    let actor = seed_actor(&pool).await;

    // Phase 1: semantic without a TTL never expires. Failed before
    // 2026-09-30 with ~168 h.
    let key = format!("ttl/semantic/{}", Uuid::new_v4());
    run_one_node(&pool, actor, envelope(&key, "semantic", None)).await;
    assert_eq!(
        expiry_after_write(&pool, actor, &key).await,
        None,
        "a semantic envelope write without ttl_hours must not expire"
    );

    // Phase 2: episodic without a TTL keeps the documented 168 h default.
    let key = format!("ttl/episodic/{}", Uuid::new_v4());
    run_one_node(&pool, actor, envelope(&key, "episodic", None)).await;
    assert_hours(
        expiry_after_write(&pool, actor, &key).await,
        168,
        "episodic default",
    );

    // Phase 3: working without a TTL also keeps 168 h (the envelope's default,
    // not the store's 1 h type default).
    let key = format!("ttl/working/{}", Uuid::new_v4());
    run_one_node(&pool, actor, envelope(&key, "working", None)).await;
    assert_hours(
        expiry_after_write(&pool, actor, &key).await,
        168,
        "working default",
    );

    // Phase 4: an explicit TTL on a semantic write is honoured.
    let key = format!("ttl/semantic-explicit/{}", Uuid::new_v4());
    run_one_node(&pool, actor, envelope(&key, "semantic", Some(2.0))).await;
    assert_hours(
        expiry_after_write(&pool, actor, &key).await,
        2,
        "explicit semantic TTL",
    );
}
