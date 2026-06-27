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
