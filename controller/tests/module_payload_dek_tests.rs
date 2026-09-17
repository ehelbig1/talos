// Per-org root DEKs — module_executions payload cutover (end-to-end).
// Proves a module payload encrypts as format v4 under the WORKFLOW's org root DEK
// (the execution tenant, resolved via workflow_execution_id) and decrypts back,
// and that an org-less (no workflow execution) payload stays v3 global.
// Runs in CI via `scripts/test-integration.sh` (TC_TESTS) — testcontainers, not
// DATABASE_URL. (The previous "Env-gated (runs in quality.yml)" claim was false:
// no runner named this binary until 2026-07-30.)

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
         VALUES ($1, $2, $3, 'completed', 'manual', $4, $5, $6, $7, 3)",
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

    // Package CJ control: the same shape still RUNNING is not swept — its
    // completion will seal the output under the key it reads from the row, so
    // a re-key landing between that read and its UPDATE would split the row.
    let running = Uuid::new_v4();
    let v3_running = encrypt_payload_bundle(Some(&sm), running, None, Some(&input), None, None)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO module_executions \
         (id, module_id, user_id, status, trigger_type, workflow_execution_id, actor_id, \
          input_data_enc, payload_enc_key_id, payload_format) \
         VALUES ($1, $2, $3, 'running', 'manual', $4, $5, $6, $7, 3)",
    )
    .bind(running)
    .bind(module)
    .bind(user)
    .bind(wei)
    .bind(actor)
    .bind(v3_running.input_enc.as_deref())
    .bind(v3_running.key_id)
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
    let (running_fmt, running_kid): (i16, Uuid) = sqlx::query_as(
        "SELECT payload_format, payload_enc_key_id FROM module_executions WHERE id=$1",
    )
    .bind(running)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (running_fmt, Some(running_kid)),
        (3, v3_running.key_id),
        "an in-flight row must not be re-keyed under its completion write"
    );
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

    // Package CE: after an org DEK rotation the payload is pending again and
    // the sweep re-keys it onto the new active DEK.
    let new_key = sm
        .rotate_dek_for_org(org, None)
        .await
        .unwrap()
        .expect("the org exists");
    let pending = sm
        .dek_migration_status()
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.table == "module_executions.payloads")
        .map(|e| e.pending)
        .unwrap();
    assert!(pending >= 1, "a payload under a retired org DEK is pending");
    let stats = service.re_encrypt_module_payloads_to_org().await.unwrap();
    assert_eq!(stats.failed, 0);
    let (fmt2, kid2): (i16, Uuid) = sqlx::query_as(
        "SELECT payload_format, payload_enc_key_id FROM module_executions WHERE id=$1",
    )
    .bind(meid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((fmt2, kid2), (4, new_key), "re-keyed onto the active DEK");
    assert_ne!(kid2, kid);
    let enc2: Vec<u8> =
        sqlx::query_scalar("SELECT input_data_enc FROM module_executions WHERE id=$1")
            .bind(meid)
            .fetch_one(&pool)
            .await
            .unwrap();
    let dec2 = decrypt_payload_slot(&sm, kid2, &enc2, meid, PayloadSlot::Input, fmt2)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&dec2).unwrap(),
        input,
        "value must survive the re-key"
    );
}

// ── Package CJ (2026-09-17): one key per row ──────────────────────────────
//
// A `module_executions` row seals its input when the module starts and its
// output when it completes; all three slots share ONE `payload_enc_key_id` /
// `payload_format`, and the completion UPDATE keeps the row's key. Until CJ the
// completion write chose its key afresh, so whenever that choice differed from
// the start's — the org lookup answered differently, or the org DEK rotated
// mid-module — the row named one key over an output sealed under another. On
// the reference deployment 2 of 61 584 rows were in that state.

struct Seeded {
    org: Uuid,
    user: Uuid,
    wf: Uuid,
    actor: Uuid,
    module: Uuid,
}

async fn seed(pool: &sqlx::PgPool) -> Seeded {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("cj-{user}@talos.test"))
    .execute(pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $1, $2, true) RETURNING id",
    )
    .bind(format!("cjorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap();
    let wf = Uuid::new_v4();
    sqlx::query("INSERT INTO workflows (id, user_id, name, module_uri, graph_json, org_id) VALUES ($1, $2, 'wf', 'm', '{}', $3)")
        .bind(wf).bind(user).bind(org).execute(pool).await.unwrap();
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, 'a', $3)")
        .bind(actor)
        .bind(user)
        .bind(org)
        .execute(pool)
        .await
        .unwrap();
    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("m-{module}"))
        .execute(pool)
        .await
        .unwrap();
    Seeded {
        org,
        user,
        wf,
        actor,
        module,
    }
}

async fn insert_workflow_execution(pool: &sqlx::PgPool, s: &Seeded, wei: Uuid) {
    sqlx::query("INSERT INTO workflow_executions (id, workflow_id, user_id, status, actor_id) VALUES ($1, $2, $3, 'running', $4)")
        .bind(wei).bind(s.wf).bind(s.user).bind(s.actor).execute(pool).await.unwrap();
}

/// Read the row back and decrypt BOTH slots under the key and format the row
/// names — the reader's only view of the row.
async fn row_slots(
    pool: &sqlx::PgPool,
    sm: &controller::secrets::SecretsManager,
    meid: Uuid,
) -> (Uuid, i16, serde_json::Value, serde_json::Value) {
    let (kid, fmt, input_enc, output_enc): (Uuid, i16, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload_enc_key_id, payload_format, input_data_enc, output_data_enc \
         FROM module_executions WHERE id = $1",
    )
    .bind(meid)
    .fetch_one(pool)
    .await
    .unwrap();
    let input = decrypt_payload_slot(sm, kid, &input_enc, meid, PayloadSlot::Input, fmt)
        .await
        .expect("input decrypts under the key the row names");
    let output = decrypt_payload_slot(sm, kid, &output_enc, meid, PayloadSlot::Output, fmt)
        .await
        .expect("output decrypts under the key the row names");
    (
        kid,
        fmt,
        serde_json::from_str(&input).unwrap(),
        serde_json::from_str(&output).unwrap(),
    )
}

/// The service writer (`create_execution` → `complete_execution`), in both
/// shapes that split a row: a start whose org lookup found no parent yet (the
/// live shape — the module row started ~1.5 ms after its workflow execution),
/// and an org DEK rotation while the module runs.
#[tokio::test]
async fn service_completion_seals_the_output_under_the_rows_key() {
    master_key();
    let pool = test_helpers::get_isolated_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    let s = seed(&pool).await;
    let service = talos_module_executions::ModuleExecutionService::new(
        pool.clone(),
        Arc::new(talos_dlp_provider::DlpService::from_env()),
    )
    .with_encryption(sm.clone());
    let input = serde_json::json!({ "in": "cj-input" });
    let output = serde_json::json!({ "out": "cj-output" });

    // (a) parent not visible at start → global v3; visible at completion.
    let wei = Uuid::new_v4();
    let meid = Uuid::new_v4();
    service
        .create_execution(
            s.module,
            s.user,
            meid,
            talos_module_executions::TriggerType::Manual,
            None,
            Some(input.clone()),
            Some(wei),
            Some(s.actor),
        )
        .await
        .unwrap();
    insert_workflow_execution(&pool, &s, wei).await;
    service
        .complete_execution(meid, s.user, Some(output.clone()), None, None)
        .await
        .unwrap();
    let global = sm.get_active_dek().await.unwrap();
    let (kid, fmt, got_in, got_out) = row_slots(&pool, &sm, meid).await;
    assert_eq!(
        (kid, fmt),
        (global.id, 3),
        "the row keeps its start-time key and format"
    );
    assert_eq!(got_in, input);
    assert_eq!(got_out, output);

    // (b) org DEK rotated while the module runs.
    let wei2 = Uuid::new_v4();
    insert_workflow_execution(&pool, &s, wei2).await;
    let meid2 = Uuid::new_v4();
    service
        .create_execution(
            s.module,
            s.user,
            meid2,
            talos_module_executions::TriggerType::Manual,
            None,
            Some(input.clone()),
            Some(wei2),
            Some(s.actor),
        )
        .await
        .unwrap();
    let before = sm.get_active_dek_for_org(s.org).await.unwrap().unwrap().id;
    let after = sm.rotate_dek_for_org(s.org, None).await.unwrap().unwrap();
    assert_ne!(before, after);
    service
        .complete_execution(meid2, s.user, Some(output.clone()), None, None)
        .await
        .unwrap();
    let (kid2, fmt2, got_in2, got_out2) = row_slots(&pool, &sm, meid2).await;
    assert_eq!(
        (kid2, fmt2),
        (before, 4),
        "sealed under the retired key the row names"
    );
    assert_eq!(got_in2, input);
    assert_eq!(got_out2, output);
}

/// The engine's store (`record_started` → `record_completed`) — the production
/// writer for every workflow-dispatched module — across a mid-run rotation.
#[tokio::test]
async fn engine_store_completion_seals_the_output_under_the_rows_key() {
    use talos_workflow_engine_core::{ExecutionStartedContext, ModuleExecutionStore};
    master_key();
    let pool = test_helpers::get_isolated_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    let s = seed(&pool).await;
    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(pool.clone())
            .with_encryption(sm.clone());
    let input = serde_json::json!({ "in": "cj-engine-input" });
    let output = serde_json::json!({ "out": "cj-engine-output" });

    let wei = Uuid::new_v4();
    insert_workflow_execution(&pool, &s, wei).await;
    let meid = Uuid::new_v4();
    store
        .record_started(ExecutionStartedContext {
            id: meid,
            module_id: s.module,
            user_id: s.user,
            workflow_execution_id: wei,
            input: &input,
            trigger_type: "manual",
            race_safe_status: false,
            actor_id: Some(s.actor),
        })
        .await
        .unwrap();
    let before = sm.get_active_dek_for_org(s.org).await.unwrap().unwrap().id;
    sm.rotate_dek_for_org(s.org, None).await.unwrap().unwrap();
    store
        .record_completed(meid, "completed", &output, Some(5), None)
        .await
        .unwrap();
    let (kid, fmt, got_in, got_out) = row_slots(&pool, &sm, meid).await;
    assert_eq!((kid, fmt), (before, 4));
    assert_eq!(got_in, input);
    assert_eq!(got_out, output);
}

/// A failed org lookup is an error, never a silent fall back to the global DEK
/// for an org-scoped payload. `workflows` is renamed away on this isolated
/// clone so the lookup fails while the global DEK stays readable.
#[tokio::test]
async fn a_failed_org_lookup_is_an_error_not_the_global_key() {
    master_key();
    let pool = test_helpers::get_isolated_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    sm.get_active_dek().await.unwrap();
    let s = seed(&pool).await;
    let wei = Uuid::new_v4();
    insert_workflow_execution(&pool, &s, wei).await;
    sqlx::query("ALTER TABLE workflows RENAME TO workflows_cj_hidden")
        .execute(&pool)
        .await
        .unwrap();
    let res = encrypt_payload_bundle(
        Some(&sm),
        Uuid::new_v4(),
        Some(wei),
        Some(&serde_json::json!({ "in": 1 })),
        None,
        None,
    )
    .await;
    assert!(
        res.is_err(),
        "an unreadable org must not seal the payload under the global DEK: {:?}",
        res.map(|b| (b.key_id, b.format_version))
    );
}
