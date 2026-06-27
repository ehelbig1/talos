// Per-org root DEKs — module_executions payload cutover (end-to-end).
// Proves a module payload encrypts as format v4 under the WORKFLOW's org root DEK
// (the execution tenant, resolved via workflow_execution_id) and decrypts back,
// and that an org-less (no workflow execution) payload stays v3 global.
// Env-gated (runs in quality.yml).

mod test_helpers;

use std::sync::Arc;
use talos_module_payload_encryption::{decrypt_payload_slot, encrypt_payload_bundle, PayloadSlot};
use uuid::Uuid;

fn master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

#[tokio::test]
async fn module_payload_encrypts_v4_under_workflow_org_and_round_trips() {
    master_key();
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();

    // Seed user + org + workflow + actor + a workflow_executions row.
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("mp-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("mporg-{tag}"))
    .bind(format!("mporg-{tag}"))
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
    let wei = Uuid::new_v4();
    sqlx::query("INSERT INTO workflow_executions (id, workflow_id, user_id, status, actor_id) VALUES ($1, $2, $3, 'running', $4)")
        .bind(wei).bind(wf).bind(user).bind(actor).execute(&pool).await.unwrap();

    // Encrypt a module payload bound to that workflow execution.
    let module_exec_id = Uuid::new_v4();
    let input = serde_json::json!({ "in": "secret-payload" });
    let bundle = encrypt_payload_bundle(
        Some(&sm),
        module_exec_id,
        Some(wei),
        Some(&input),
        None,
        None,
    )
    .await
    .unwrap();

    // v4, under the workflow's org DEK.
    assert_eq!(
        bundle.format_version, 4,
        "workflow-bound payload must be v4"
    );
    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(
        bundle.key_id,
        Some(org_dek.id),
        "must use the workflow's org DEK"
    );

    // Decrypt round-trip.
    let dec = decrypt_payload_slot(
        &sm,
        bundle.key_id.unwrap(),
        bundle.input_enc.as_deref().unwrap(),
        module_exec_id,
        PayloadSlot::Input,
        bundle.format_version,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&dec).unwrap(),
        input
    );
}

#[tokio::test]
async fn module_payload_without_workflow_stays_v3_global() {
    master_key();
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();

    // No workflow_execution_id and a fresh module id with no existing row →
    // org resolves to None → global DEK (v3).
    let module_exec_id = Uuid::new_v4();
    let input = serde_json::json!({ "in": "standalone-payload" });
    let bundle = encrypt_payload_bundle(Some(&sm), module_exec_id, None, Some(&input), None, None)
        .await
        .unwrap();

    assert_eq!(bundle.format_version, 3, "org-less payload stays v3 global");
    let global = sm.get_active_dek().await.unwrap();
    assert_eq!(bundle.key_id, Some(global.id), "must use the global DEK");

    let dec = decrypt_payload_slot(
        &sm,
        bundle.key_id.unwrap(),
        bundle.input_enc.as_deref().unwrap(),
        module_exec_id,
        PayloadSlot::Input,
        bundle.format_version,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&dec).unwrap(),
        input
    );
}

#[tokio::test]
async fn re_encrypt_module_payloads_to_org_migrates_v3_global_rows_to_v4() {
    master_key();
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();

    // Seed user + org + workflow + actor + workflow_execution + module.
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("mps-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("mpsorg-{tag}")).bind(format!("mpsorg-{tag}")).bind(user)
    .fetch_one(&pool).await.unwrap();
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
    let wei = Uuid::new_v4();
    sqlx::query("INSERT INTO workflow_executions (id, workflow_id, user_id, status, actor_id) VALUES ($1, $2, $3, 'running', $4)")
        .bind(wei).bind(wf).bind(user).bind(actor).execute(&pool).await.unwrap();
    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("m-{module}"))
        .execute(&pool)
        .await
        .unwrap();

    // Craft a PRE-cutover module-execution row: v3 global input ciphertext, but
    // workflow_execution_id pointing at a workflow that HAS an org.
    let meid = Uuid::new_v4();
    let input = serde_json::json!({ "in": "legacy-payload" });
    let v3 = encrypt_payload_bundle(Some(&sm), meid, None, Some(&input), None, None)
        .await
        .unwrap();
    assert_eq!(v3.format_version, 3);
    sqlx::query(
        "INSERT INTO module_executions \
         (id, module_id, user_id, status, trigger_type, workflow_execution_id, actor_id, \
          input_data_enc, payload_enc_key_id, payload_format) \
         VALUES ($1, $2, $3, 'running', 'manual', $4, $5, $6, $7, 3)",
    )
    .bind(meid)
    .bind(module)
    .bind(user)
    .bind(wei)
    .bind(actor)
    .bind(v3.input_enc.as_deref())
    .bind(v3.key_id)
    .execute(&pool)
    .await
    .unwrap();

    // Run the sweep.
    let service = talos_module_executions::ModuleExecutionService::new(
        pool.clone(),
        Arc::new(talos_dlp_provider::DlpService::from_env()),
    )
    .with_encryption(sm.clone());
    let stats = service.re_encrypt_module_payloads_to_org().await.unwrap();
    assert!(
        stats.re_encrypted >= 1,
        "sweep must migrate at least our row"
    );
    assert_eq!(stats.failed, 0);

    // Now v4 under the workflow's org DEK, still decrypts.
    let (fmt, kid): (i16, Uuid) = sqlx::query_as(
        "SELECT payload_format, payload_enc_key_id FROM module_executions WHERE id=$1",
    )
    .bind(meid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fmt, 4, "sweep must upgrade the row to v4");
    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(kid, org_dek.id, "row must now reference the org DEK");

    let enc: Vec<u8> =
        sqlx::query_scalar("SELECT input_data_enc FROM module_executions WHERE id=$1")
            .bind(meid)
            .fetch_one(&pool)
            .await
            .unwrap();
    let dec = decrypt_payload_slot(&sm, kid, &enc, meid, PayloadSlot::Input, fmt)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&dec).unwrap(),
        input
    );
}
