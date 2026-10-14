//! A secret granted to a MODULE reaches only the jobs of the user who owns it
//! (security review 2026-10-14, C-1).
//!
//! `secrets.allowed_modules` names module ids, and a module id is not a tenant:
//! a catalog module, or one shared with an organization, is run by many users.
//! Until this date the engine's `SecretsResolver` read every secret granting the
//! module (`WHERE $1 = ANY(allowed_modules)`, no owner), so a secret user A
//! granted to a shared module was decrypted and sealed into user B's job of it.
//!
//! Driven end to end: a real `SecretsManager`, the controller's
//! `ControllerSecretsResolver`, a real engine run, and the envelope the
//! dispatched job carries, opened with the worker key the way a worker would.
//! The second half pins the write side: `allowed_modules` may only name a
//! module the writer can run.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::Arc;

use controller::secrets::SecretsManager;
use serde_json::json;
use talos_oauth::resolver::ControllerSecretsResolver;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{WasmModuleArtifact, WorkerSharedKey};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use talos_workflow_job_protocol::EncryptedSecrets;
use uuid::Uuid;

const GRANTED_PATH: &str = "svc/module_grant_token";
const WORKER_KEY: [u8; 32] = [7u8; 32];

struct World {
    pool: sqlx::PgPool,
    secrets: Arc<SecretsManager>,
    _db: common::TestDb,
}

async fn world() -> World {
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    World { pool, secrets, _db }
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@module-grant.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

/// A module row. `owner = None` is a catalog module: no owner, no org, run by
/// every user.
async fn seed_module(pool: &sqlx::PgPool, owner: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, user_id, name, kind) VALUES ($1, $2, $3, 'sandbox')")
        .bind(id)
        .bind(owner)
        .bind(format!("grant-scope-{id}"))
        .execute(pool)
        .await
        .expect("seed module");
    id
}

/// Run a one-node workflow of `module` as `user` and return the secret paths
/// the dispatched job's envelope carries, opened with the worker key.
async fn dispatched_secret_paths(
    secrets: &Arc<SecretsManager>,
    module: Uuid,
    user: Uuid,
) -> Vec<String> {
    let graph = WorkflowGraphBuilder::new()
        .add_module("node", module, Some(json!({})))
        .build()
        .expect("graph builds");
    let mut engine = minimal_engine();
    engine.set_user_id(user);
    engine.set_secrets_resolver(Arc::new(ControllerSecretsResolver::new(secrets.clone())));
    engine.set_module_fetcher(Arc::new(InMemoryModuleFetcher::new().with_module(
        module,
        WasmModuleArtifact {
            module_id: module,
            content_hash: "stub".into(),
            wasm_bytes: vec![],
            oci_url: None,
            max_fuel: 1_000_000,
            capability_world: "secrets-node".into(),
            allowed_hosts: vec![],
            allowed_methods: vec![],
            // No declared grant: anything the job carries came from the
            // module-grant (`allowed_modules`) read under test.
            allowed_secrets: vec![],
            requires_approval_for: vec![],
            integration_name: None,
            config: None,
        },
    )));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");
    let dispatcher =
        Arc::new(ScriptedDispatcher::new().with_response(module, json!({ "ok": true })));
    let execution_id = Uuid::new_v4();
    engine
        .run_with_trigger_input_transport(
            dispatcher.clone(),
            Some(WorkerSharedKey::new(WORKER_KEY.to_vec())),
            json!({}),
            execution_id,
        )
        .await
        .expect("run");

    let jobs = dispatcher.jobs();
    assert_eq!(jobs.len(), 1, "one node, one dispatch");
    let job = &jobs[0];
    // Claim-based sealing names the delivered paths in clear; the inline
    // envelope carries them encrypted. Read both so the assertion holds in
    // either sealing mode.
    let mut paths: Vec<String> = job.secret_paths.clone();
    if let Some(plain) = &job.plaintext_secrets {
        paths.extend(plain.keys().cloned());
    }
    if !job.encrypted_secrets_ciphertext.is_empty() {
        let envelope = EncryptedSecrets {
            ciphertext: job.encrypted_secrets_ciphertext.clone(),
            nonce: job.encrypted_secrets_nonce.clone(),
        };
        let opened = envelope
            .decrypt_with_aad(&WORKER_KEY, execution_id.as_bytes())
            .expect("the worker key opens the envelope");
        paths.extend(opened.into_keys());
    }
    paths.sort();
    paths.dedup();
    paths
}

#[tokio::test]
async fn a_secret_granted_to_a_shared_module_reaches_only_its_owners_jobs() {
    let w = world().await;
    let owner = seed_user(&w.pool).await;
    let other = seed_user(&w.pool).await;
    let shared = seed_module(&w.pool, None).await;

    w.secrets
        .create_secret(
            "module grant token",
            GRANTED_PATH,
            "owner-only-value",
            None,
            owner,
            vec![shared],
            None,
        )
        .await
        .expect("owner grants their secret to a catalog module");

    let others_job = dispatched_secret_paths(&w.secrets, shared, other).await;
    assert!(
        !others_job.iter().any(|p| p == GRANTED_PATH),
        "another user's job of the shared module carried the owner's secret: {others_job:?}"
    );

    let owners_job = dispatched_secret_paths(&w.secrets, shared, owner).await;
    assert!(
        owners_job.iter().any(|p| p == GRANTED_PATH),
        "the owner's own job lost the secret they granted: {owners_job:?}"
    );
}

#[tokio::test]
async fn a_module_grant_read_with_no_user_returns_only_system_secrets() {
    let w = world().await;
    let owner = seed_user(&w.pool).await;
    let shared = seed_module(&w.pool, None).await;
    w.secrets
        .create_secret("t", GRANTED_PATH, "v", None, owner, vec![shared], None)
        .await
        .expect("grant");

    let none = w
        .secrets
        .get_module_secrets_for(shared, None)
        .await
        .expect("read");
    assert!(
        !none.contains_key(GRANTED_PATH),
        "a user-less read returned a user's secret"
    );
}

#[tokio::test]
async fn allowed_modules_may_name_only_a_module_the_writer_can_run() {
    let w = world().await;
    let writer = seed_user(&w.pool).await;
    let victim = seed_user(&w.pool).await;
    let victims_module = seed_module(&w.pool, Some(victim)).await;
    let own_module = seed_module(&w.pool, Some(writer)).await;
    let catalog_module = seed_module(&w.pool, None).await;

    // Another user's private module: refused, and nothing is written.
    let err = w
        .secrets
        .create_secret(
            "p",
            "svc/poison",
            "v",
            None,
            writer,
            vec![victims_module],
            None,
        )
        .await
        .expect_err("a grant to another user's module must be refused");
    assert!(
        err.to_string().starts_with("Validation:"),
        "the refusal is a caller-facing validation message: {err}"
    );
    let written: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secrets WHERE key_path = $1")
        .bind("svc/poison")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(written, 0, "a refused grant wrote a row");

    // An id that names no module: refused with the same message.
    let unknown = w
        .secrets
        .create_secret(
            "u",
            "svc/unknown",
            "v",
            None,
            writer,
            vec![Uuid::new_v4()],
            None,
        )
        .await
        .expect_err("an unknown module id must be refused");
    assert_eq!(
        unknown.to_string(),
        err.to_string(),
        "one reason for every miss"
    );

    // The upsert writer applies the same rule.
    w.secrets
        .upsert_secret(
            "p",
            "svc/poison2",
            "v",
            "default",
            None,
            writer,
            vec![victims_module],
            None,
        )
        .await
        .expect_err("upsert must refuse a grant to another user's module");

    // The writer's own module and a catalog module are allowed.
    w.secrets
        .create_secret(
            "ok",
            "svc/allowed",
            "v",
            None,
            writer,
            vec![own_module, catalog_module],
            None,
        )
        .await
        .expect("a grant to the writer's own module and a catalog module");
}
