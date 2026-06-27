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

#[tokio::test]
async fn re_encrypt_outputs_to_org_migrates_v3_global_rows_to_v4() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();

    // Seed user + org + workflow + actor + a running execution.
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("wfsweep-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("wfsweeporg-{tag}"))
    .bind(format!("wfsweeporg-{tag}"))
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    let wf = Uuid::new_v4();
    sqlx::query("INSERT INTO workflows (id, user_id, name, module_uri, graph_json, org_id) VALUES ($1, $2, 'wf', 'm', '{}', $3)")
        .bind(wf).bind(user).bind(org).execute(&pool).await.unwrap();
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, 'a', $3)")
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

    // Craft a PRE-cutover output: v3 global ciphertext.
    let output = serde_json::json!({ "result": "legacy-output" });
    let (kid, ct, ver) = sm
        .encrypt_value_aad_v3(&serde_json::to_string(&output).unwrap(), exec.as_bytes())
        .await
        .unwrap();
    assert_eq!(ver, 3);
    sqlx::query(
        "UPDATE workflow_executions SET output_data = NULL, output_data_enc = $1, \
         output_enc_key_id = $2, output_data_format = 3 WHERE id = $3",
    )
    .bind(ct.as_slice())
    .bind(kid)
    .bind(exec)
    .execute(&pool)
    .await
    .unwrap();

    // Sweep.
    let stats = repo.re_encrypt_outputs_to_org().await.unwrap();
    assert!(
        stats.re_encrypted >= 1,
        "sweep must migrate at least our row"
    );
    assert_eq!(stats.failed, 0);

    // Now v4 under the workflow's org DEK, still decrypts.
    let (fmt, rkid): (i16, Uuid) = sqlx::query_as(
        "SELECT output_data_format, output_enc_key_id FROM workflow_executions WHERE id=$1",
    )
    .bind(exec)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fmt, 4, "sweep must upgrade the row to v4");
    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(rkid, org_dek.id, "row must now reference the org DEK");

    let row = repo
        .get_execution(exec, user)
        .await
        .unwrap()
        .expect("execution row");
    assert_eq!(
        row.output_data,
        Some(output),
        "value must survive the sweep"
    );
}
