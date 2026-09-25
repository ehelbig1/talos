//! `enqueue_workflow` runs only rows it claimed, and runs them AS the actor
//! the authorization gate resolved.
//!
//! Two defects in one handler, both found by the 2026-09-25 review:
//!
//!  1. The drain called `mark_execution_running_from_queued` — an UPDATE
//!     guarded by `status = 'queued'` whose `bool` says whether THIS drain owns
//!     the run — logged the `Err`, discarded the `bool`, and dispatched anyway.
//!     A row the operator cancelled while it waited was run regardless.
//!  2. The gate ran only when the caller named an `actor_id`, and the drain
//!     built its engine with `EngineOpts::for_run` and NO actor. A workflow
//!     bound to a `readonly` / `minimal-node` actor, enqueued without naming
//!     one, skipped the capability ceiling and ran unbound.
//!
//! (1) is driven through the extracted `drain_enqueued_batch` against a real
//! database, with the run replaced by a recorder, so the assertion is on which
//! rows WOULD have been dispatched. (2) is driven through the real MCP
//! dispatch over a real `McpState`. `common` (DATABASE_URL) harness, so
//! CTRL_TESTS and not TC_TESTS (64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcp_common::{agent, error_message, mcp_state, text_json};
use talos_execution_repository::ExecutionRepository;
use talos_mcp_handlers::executions::{drain_enqueued_batch, EnqueueClaim, EnqueueDrainSummary};
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("enqueue-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &sqlx::PgPool, user: Uuid, max_world: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("enqueue-actor-{id}"))
    .bind(max_world)
    .execute(pool)
    .await
    .expect("seed actor");
    id
}

async fn seed_module(pool: &sqlx::PgPool, user: Uuid, world: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world) \
         VALUES ($1, $2, $3, 'sandbox', $4)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("enqueue-module-{id}"))
    .bind(world)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

/// An active, enabled workflow whose one node runs `module`, bound to `actor`.
async fn seed_workflow(pool: &sqlx::PgPool, user: Uuid, module: Uuid, actor: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let graph = serde_json::json!({
        "nodes": [{ "id": "only", "type": module.to_string() }],
        "edges": [],
    });
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, status, is_enabled, actor_id) \
         VALUES ($1, $2, $3, 'test:enqueue', $4, 'active', true, $5)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("enqueue-wf-{id}"))
    .bind(graph.to_string())
    .bind(actor)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn status(pool: &sqlx::PgPool, exec: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM workflow_executions WHERE id = $1")
        .bind(exec)
        .fetch_one(pool)
        .await
        .expect("status")
}

async fn rows_for(pool: &sqlx::PgPool, wf: Uuid) -> Vec<(Uuid, Option<Uuid>)> {
    sqlx::query_as("SELECT id, actor_id FROM workflow_executions WHERE workflow_id = $1")
        .bind(wf)
        .fetch_all(pool)
        .await
        .expect("rows")
}

/// Admit `n` queued rows through the same batch helper the handler uses.
async fn queued_rows(pool: &sqlx::PgPool, n: usize) -> Vec<Uuid> {
    let user = seed_user(pool).await;
    let actor = seed_actor(pool, user, "automation-node").await;
    let module = seed_module(pool, user, "minimal-node").await;
    let wf = seed_workflow(pool, user, module, actor).await;
    let ids: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
    let admission = WorkflowRepository::new(pool.clone())
        .create_executions_batch_under_concurrency_limit(&ids, wf, user, None, Some(actor))
        .await
        .expect("batch admission");
    assert_eq!(admission.inserted, n, "fixture: every row admitted");
    for id in &ids {
        assert_eq!(status(pool, *id).await, "queued");
    }
    ids
}

/// Drain `ids` with the run replaced by a recorder; returns what it recorded.
async fn drain_recording(
    repo: &ExecutionRepository,
    ids: &[Uuid],
) -> (EnqueueDrainSummary, Vec<Uuid>) {
    let ran = Arc::new(Mutex::new(Vec::new()));
    let items = ids.iter().map(|id| (serde_json::json!({}), *id)).collect();
    let summary = drain_enqueued_batch(repo, items, Duration::ZERO, |_, id| {
        let ran = ran.clone();
        async move { ran.lock().unwrap().push(id) }
    })
    .await;
    let ran = ran.lock().unwrap().clone();
    (summary, ran)
}

// ── (1) the claim decides dispatch ──────────────────────────────────

#[tokio::test]
async fn a_row_cancelled_while_queued_is_never_dispatched() {
    let (pool, _db) = common::isolated_db_pool().await;
    let ids = queued_rows(&pool, 3).await;
    let repo = ExecutionRepository::new(pool.clone());

    // The operator cancels the middle row while it waits its turn.
    let user: Uuid = sqlx::query_scalar("SELECT user_id FROM workflow_executions WHERE id = $1")
        .bind(ids[1])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(repo.mark_execution_cancelled(ids[1], user).await.unwrap());

    let (summary, ran) = drain_recording(&repo, &ids).await;

    assert_eq!(
        ran,
        vec![ids[0], ids[2]],
        "only the rows this drain claimed may run — the cancelled one was dispatched"
    );
    assert_eq!(
        summary,
        EnqueueDrainSummary {
            dispatched: 2,
            skipped_not_queued: 1,
            refused_unreadable: 0,
        }
    );
    assert_eq!(
        status(&pool, ids[1]).await,
        "cancelled",
        "the cancel stands"
    );
    // CONTROL: the claimed rows really were moved to `running`.
    assert_eq!(status(&pool, ids[0]).await, "running");
    assert_eq!(status(&pool, ids[2]).await, "running");
}

#[tokio::test]
async fn a_claim_that_cannot_be_read_dispatches_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let ids = queued_rows(&pool, 2).await;
    // A repository over a CLOSED pool: every claim is an `Err`.
    let closed = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .unwrap();
    closed.close().await;
    let repo = ExecutionRepository::new(closed);

    let (summary, ran) = drain_recording(&repo, &ids).await;

    assert!(
        ran.is_empty(),
        "fail CLOSED: an unreadable claim must not run ({ran:?})"
    );
    assert_eq!(summary.refused_unreadable, 2);
    assert_eq!(summary.dispatched, 0);
    // The rows were never touched through the closed pool.
    for id in ids {
        assert_eq!(status(&pool, id).await, "queued");
    }
}

#[test]
fn the_claim_decision_is_three_valued() {
    assert_eq!(EnqueueClaim::from_claim(&Ok(true)), EnqueueClaim::Claimed);
    assert_eq!(
        EnqueueClaim::from_claim(&Ok(false)),
        EnqueueClaim::NotQueued
    );
    assert_eq!(
        EnqueueClaim::from_claim(&Err(anyhow::anyhow!("pool timed out"))),
        EnqueueClaim::Unreadable
    );
}

// ── (2) the resolved actor gates, stamps and binds ──────────────────

async fn enqueue(
    state: &talos_mcp_handlers::McpState,
    user: Uuid,
    wf: Uuid,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::executions::dispatch(
        "enqueue_workflow",
        Some(serde_json::json!(1)),
        // No `actor_id`: the case that skipped the gate.
        &serde_json::json!({ "workflow_id": wf.to_string(), "inputs": [{}] }),
        state,
        agent(user),
    )
    .await
    .expect("enqueue_workflow is dispatched")
}

/// With `TALOS_TEST_NATS_URL` set (it is under `scripts/test-integration.sh`)
/// the state gets a real NATS client, so a permitted enqueue really admits
/// rows; without it the permitted case stops at "NATS client not available",
/// which is reached only AFTER the gate.
async fn state_for(pool: &sqlx::PgPool) -> (talos_mcp_handlers::McpState, bool) {
    let mut state = mcp_state(pool.clone()).await;
    let nats = match std::env::var("TALOS_TEST_NATS_URL") {
        Ok(url) => Some(Arc::new(async_nats::connect(url).await.expect("nats"))),
        Err(_) => None,
    };
    let has_nats = nats.is_some();
    state.nats_client = nats;
    (state, has_nats)
}

#[tokio::test]
async fn an_enqueue_naming_no_actor_is_held_to_the_workflows_bound_actor_ceiling() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user, "minimal-node").await;
    let module = seed_module(&pool, user, "http-node").await;
    let wf = seed_workflow(&pool, user, module, actor).await;
    let (state, _) = state_for(&pool).await;

    let resp = enqueue(&state, user, wf).await;

    let msg = error_message(&resp);
    assert!(
        msg.contains("Cannot enqueue: module") && msg.contains("minimal-node"),
        "the bound actor's ceiling refuses the http-node module: {msg}"
    );
    assert!(
        rows_for(&pool, wf).await.is_empty(),
        "a refused enqueue writes no rows"
    );
}

#[tokio::test]
async fn control_a_permitted_enqueue_stamps_the_workflows_bound_actor() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user, "http-node").await;
    let module = seed_module(&pool, user, "http-node").await;
    let wf = seed_workflow(&pool, user, module, actor).await;
    let (state, has_nats) = state_for(&pool).await;

    let resp = enqueue(&state, user, wf).await;

    if !has_nats {
        assert_eq!(
            error_message(&resp),
            "NATS client not available",
            "the gate admitted the permitted actor and stopped at the NATS check below it"
        );
        return;
    }
    assert_eq!(text_json(&resp)["queued"], 1, "admitted: {resp:?}");
    let rows = rows_for(&pool, wf).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].1,
        Some(actor),
        "the row runs as the workflow's bound actor — the value every drained \
         engine is bound to — not the user's default"
    );
}
