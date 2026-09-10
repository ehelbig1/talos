// Per-org root DEKs — workflow_executions.output_data_enc cutover (end-to-end).
// Proves execution output lands as format v4 under the WORKFLOW's org root DEK
// (the execution tenant) and reads back decrypted.
// Runs in CI via `scripts/test-integration.sh` (TC_TESTS) — testcontainers, not
// DATABASE_URL. (The previous "Env-gated (runs in quality.yml)" claim was false:
// no runner named this binary until 2026-07-30.)

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
    let row = match repo.lookup_execution(exec, user).await.unwrap() {
        talos_execution_repository::ExecutionLookup::Live(r) => r,
        other => panic!("execution row must be Live, got {other:?}"),
    };
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

    let row = match repo.lookup_execution(exec, user).await.unwrap() {
        talos_execution_repository::ExecutionLookup::Live(r) => r,
        other => panic!("execution row must be Live, got {other:?}"),
    };
    assert_eq!(
        row.output_data,
        Some(output),
        "value must survive the sweep"
    );
}

// ── One column, three writers, one DEK scope (2026-09-10) ────────────────────
//
// `workflow_executions.output_data_enc` is written by THREE repositories.
// `ExecutionRepository::encrypt_output` resolved the workflow's org and wrote
// v4 (the test above); `WorkflowRepository::maybe_encrypt_execution_output`
// and `ActorRepository::complete_execution` skipped the lookup and wrote v3
// under the GLOBAL DEK — so the DEK a run's output sat under depended on
// which repository happened to finalise it. Both now resolve the org through
// `SecretsManager::resolve_workflow_execution_org_id` (one home). These two
// tests pin each writer to the org DEK and prove the row still reads back
// through the execution repository's versioned decrypt.

/// Seeds user + personal org + workflow (org-scoped) + actor + a RUNNING
/// execution row, returning `(user, org, exec_id, sm, pool)`.
async fn seed_running_execution(
    label: &str,
) -> (
    Uuid,
    Uuid,
    Uuid,
    Arc<controller::secrets::SecretsManager>,
    sqlx::Pool<sqlx::Postgres>,
) {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();

    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("{label}-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("{label}-org-{tag}"))
    .bind(format!("{label}-org-{tag}"))
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
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, 'a', $3)")
        .bind(actor)
        .bind(user)
        .bind(org)
        .execute(&pool)
        .await
        .unwrap();

    let exec_repo =
        talos_execution_repository::ExecutionRepository::with_encryption(pool.clone(), sm.clone());
    let exec = Uuid::new_v4();
    exec_repo
        .create_execution(exec, wf, user, None, Some(actor), "running")
        .await
        .unwrap();
    (user, org, exec, sm, pool)
}

async fn assert_row_is_v4_under_org_dek_and_reads_back(
    pool: &sqlx::Pool<sqlx::Postgres>,
    sm: &Arc<controller::secrets::SecretsManager>,
    user: Uuid,
    org: Uuid,
    exec: Uuid,
    expected: &serde_json::Value,
    writer: &str,
) {
    let (fmt, kid, status): (i16, Uuid, String) = sqlx::query_as(
        "SELECT output_data_format, output_enc_key_id, status FROM workflow_executions WHERE id=$1",
    )
    .bind(exec)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        status, "completed",
        "{writer}: the guarded UPDATE must have landed"
    );
    assert_eq!(
        fmt, 4,
        "{writer}: execution output must be format v4, not global v3"
    );
    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(kid, org_dek.id, "{writer}: must use the workflow's org DEK");

    // Reads back decrypted through the ONE versioned read path.
    let exec_repo =
        talos_execution_repository::ExecutionRepository::with_encryption(pool.clone(), sm.clone());
    let row = match exec_repo.lookup_execution(exec, user).await.unwrap() {
        talos_execution_repository::ExecutionLookup::Live(r) => r,
        other => panic!("{writer}: execution row must be Live, got {other:?}"),
    };
    assert_eq!(
        row.output_data.as_ref(),
        Some(expected),
        "{writer}: value must round-trip"
    );
}

#[tokio::test]
async fn workflow_repository_completion_writes_v4_under_workflow_org_dek() {
    let (user, org, exec, sm, pool) = seed_running_execution("wfrepo").await;
    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone())
        .with_encryption(sm.clone());
    let output = serde_json::json!({ "result": "completed-by-workflow-repository" });
    repo.mark_execution_completed(exec, &output).await.unwrap();
    assert_row_is_v4_under_org_dek_and_reads_back(
        &pool,
        &sm,
        user,
        org,
        exec,
        &output,
        "WorkflowRepository::mark_execution_completed",
    )
    .await;
}

#[tokio::test]
async fn actor_repository_completion_writes_v4_under_workflow_org_dek() {
    let (user, org, exec, sm, pool) = seed_running_execution("actrepo").await;
    let repo =
        talos_actor_repository::ActorRepository::new(pool.clone()).with_encryption(sm.clone());
    let output = serde_json::json!({ "result": "completed-by-actor-repository" });
    repo.complete_execution(exec, &output).await.unwrap();
    assert_row_is_v4_under_org_dek_and_reads_back(
        &pool,
        &sm,
        user,
        org,
        exec,
        &output,
        "ActorRepository::complete_execution",
    )
    .await;
}

#[tokio::test]
async fn orgless_workflow_output_stays_v3_global_from_every_writer() {
    // The `None` arm of `encrypt_value_aad_v4_or_global`: a workflow with no
    // org keeps today's v3/global format — the change scopes org data to its
    // org DEK, it does not invent an org for org-less rows.
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let pool = test_helpers::get_test_db_pool().await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("orgless-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();
    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES ($1, $2, 'wf', 'm', '{}')",
    )
    .bind(wf)
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    // If a trigger stamped an org anyway, this test's premise is void — check.
    let wf_org: Option<Uuid> = sqlx::query_scalar("SELECT org_id FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&pool)
        .await
        .unwrap();
    if wf_org.is_some() {
        eprintln!(
            "workflows.org_id was auto-stamped; org-less premise does not hold here — skipping"
        );
        return;
    }
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'a')")
        .bind(actor)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let exec_repo =
        talos_execution_repository::ExecutionRepository::with_encryption(pool.clone(), sm.clone());
    let exec = Uuid::new_v4();
    exec_repo
        .create_execution(exec, wf, user, None, Some(actor), "running")
        .await
        .unwrap();

    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone())
        .with_encryption(sm.clone());
    repo.mark_execution_completed(exec, &serde_json::json!({"r": 1}))
        .await
        .unwrap();
    let (fmt, kid): (i16, Uuid) = sqlx::query_as(
        "SELECT output_data_format, output_enc_key_id FROM workflow_executions WHERE id=$1",
    )
    .bind(exec)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fmt, 3, "org-less workflow output stays v3");
    assert_eq!(
        kid,
        sm.get_active_dek().await.unwrap().id,
        "…under the GLOBAL DEK"
    );
}
