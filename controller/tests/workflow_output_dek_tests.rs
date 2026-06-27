// Per-org root DEKs — workflow_executions.output_data_enc cutover (end-to-end).
// Proves execution output lands as format v4 under the WORKFLOW's org root DEK
// (the execution tenant) and reads back decrypted. Env-gated (runs in quality.yml).

mod test_helpers;

use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn workflow_output_writes_v4_under_workflow_org_dek_and_reads_back() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();

    // Seed user + org + workflow (workflows always carry org_id).
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("wf-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("wforg-{tag}"))
    .bind(format!("wforg-{tag}"))
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, org_id) \
         VALUES ($1, $2, 'wf', 'm', '{}', $3)",
    )
    .bind(wf)
    .bind(user)
    .bind(org)
    .execute(&pool)
    .await
    .unwrap();

    // workflow_executions.actor_id is NOT NULL (actor arc) — seed an actor.
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, 'wf-actor', $3)")
        .bind(actor)
        .bind(user)
        .bind(org)
        .execute(&pool)
        .await
        .unwrap();

    let repo =
        talos_execution_repository::ExecutionRepository::with_encryption(pool.clone(), sm.clone());
    let exec = Uuid::new_v4();
    repo.create_execution(exec, wf, user, None, Some(actor), "running")
        .await
        .unwrap();

    let output = serde_json::json!({ "result": "top-secret-output" });
    repo.mark_execution_waiting(exec, &output).await.unwrap();

    // Row is v4, keyed by the workflow's org DEK (resolved via the workflow join;
    // workflow_executions.org_id itself stays NULL by the perf-exclusion design).
    let (fmt, kid): (i16, Uuid) = sqlx::query_as(
        "SELECT output_data_format, output_enc_key_id FROM workflow_executions WHERE id=$1",
    )
    .bind(exec)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fmt, 4, "execution output must be format v4");
    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(kid, org_dek.id, "must use the workflow's org DEK");

    // Reads back decrypted through the versioned path.
    let row = repo
        .get_execution(exec, user)
        .await
        .unwrap()
        .expect("execution row present");
    assert_eq!(row.output_data, Some(output));
}
