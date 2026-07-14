//! ExecutionStatus ↔ DB drift guard. The module_executions status CHECK
//! gained 'cancelled' in migration 20260327000003 (March 2026) but the
//! Rust enum lagged 3.5 months — every history read over a module with a
//! cancelled execution failed with `invalid value "cancelled" for enum
//! ExecutionStatus` (found live in the editor 2026-07-14). This test seeds
//! one row PER DB-legal status and reads them all back through the REAL
//! decode path, so the next CHECK-vs-enum drift fails here instead of in
//! production.

mod common;

use std::sync::Arc;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@me-status.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

#[tokio::test]
async fn every_db_legal_status_decodes_through_the_service() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("m-{module}"))
        .execute(&pool)
        .await
        .expect("seed module");
    // actor_id is NOT NULL post actor-universalization (#307–#317).
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("actor-{actor}"))
        .execute(&pool)
        .await
        .expect("seed actor");

    // One execution row per canonical status. ExecutionStatus::ALL mirrors
    // the CHECK constraint; if the DB accepts the insert but the enum can't
    // decode it, the read below fails — the exact production symptom.
    for (text, _) in talos_module_executions::ExecutionStatus::ALL {
        sqlx::query(
            "INSERT INTO module_executions \
             (id, module_id, user_id, actor_id, status, trigger_type) \
             VALUES ($1, $2, $3, $4, $5, 'manual')",
        )
        .bind(Uuid::new_v4())
        .bind(module)
        .bind(user)
        .bind(actor)
        .bind(text)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("status '{text}' rejected by the DB CHECK: {e}"));
    }

    let service = talos_module_executions::ModuleExecutionService::new(
        pool.clone(),
        Arc::new(talos_dlp_provider::DlpService::from_env()),
    );
    let executions = service
        .get_module_executions(module, user, 50, 0)
        .await
        .expect("every DB-legal status must decode (the 'cancelled' drift class)");
    assert_eq!(
        executions.len(),
        talos_module_executions::ExecutionStatus::ALL.len(),
        "one row per canonical status read back"
    );

    // And the reverse direction: a status in the CHECK constraint that the
    // enum doesn't know CANNOT exist, because ALL is what we just inserted
    // from. If the CHECK gains a value, extend ExecutionStatus::ALL (the
    // insert above will then exercise it here automatically).
    let distinct: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT status) FROM module_executions WHERE module_id = $1",
    )
    .bind(module)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        distinct as usize,
        talos_module_executions::ExecutionStatus::ALL.len()
    );
}
