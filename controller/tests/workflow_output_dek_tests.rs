// Per-org root DEKs — workflow_executions.output_data_enc cutover (end-to-end).
// Proves execution output lands as format v4 under the WORKFLOW's org root DEK
// (the execution tenant) and reads back decrypted.
// Runs in CI via `scripts/test-integration.sh` (TC_TESTS) — testcontainers, not
// DATABASE_URL. (The previous "Env-gated (runs in quality.yml)" claim was false:
// no runner named this binary until 2026-07-30.)

mod test_helpers;

use std::sync::Arc;
use uuid::Uuid;

/// A running execution row for these fixtures. Package CK deleted
/// `ExecutionRepository::create_execution` — it had no production caller, and
/// an ungated `pub` INSERT into `workflow_executions` is the shape the package
/// removes — so the fixture writes its own row.
async fn insert_running_execution(
    pool: &sqlx::PgPool,
    exec: Uuid,
    wf: Uuid,
    user: Uuid,
    actor: Uuid,
) {
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, started_at, actor_id) \
         VALUES ($1, $2, $3, 'running', NOW(), $4)",
    )
    .bind(exec)
    .bind(wf)
    .bind(user)
    .bind(actor)
    .execute(pool)
    .await
    .unwrap();
}

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
    insert_running_execution(&pool, exec, wf, user, actor).await;

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
    insert_running_execution(&pool, exec, wf, user, actor).await;

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
        Some(output.clone()),
        "value must survive the sweep"
    );

    // Package CE: after an org DEK rotation the output is pending again and
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
        .find(|e| e.table == "workflow_executions.output")
        .map(|e| e.pending)
        .unwrap();
    assert!(pending >= 1, "an output under a retired org DEK is pending");
    let stats = repo.re_encrypt_outputs_to_org().await.unwrap();
    assert_eq!(stats.failed, 0);
    let (fmt2, kid2): (i16, Uuid) = sqlx::query_as(
        "SELECT output_data_format, output_enc_key_id FROM workflow_executions WHERE id=$1",
    )
    .bind(exec)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((fmt2, kid2), (4, new_key), "re-keyed onto the active DEK");
    assert_ne!(kid2, rkid);
    let row = match repo.lookup_execution(exec, user).await.unwrap() {
        talos_execution_repository::ExecutionLookup::Live(r) => r,
        other => panic!("execution row must be Live, got {other:?}"),
    };
    assert_eq!(
        row.output_data,
        Some(output),
        "value must survive the re-key"
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

    let exec = Uuid::new_v4();
    insert_running_execution(&pool, exec, wf, user, actor).await;
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
    let exec = Uuid::new_v4();
    insert_running_execution(&pool, exec, wf, user, actor).await;

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

// ── The archive tier (2026-09-18) ───────────────────────────────────────────
//
// The retention sweep MOVES a terminal execution into
// `workflow_executions_archive` with its ciphertext, key id and format
// unchanged. The per-org output sweep and `dek_migration_status` read the LIVE
// table only, so an archived output stayed on the global DEK (or an org DEK
// `rotateOrgDek` had retired) and the status called the work done. Both now
// cover the archive; these tests archive through the production move.

/// Seal `value` as a pre-cutover v3 GLOBAL output on `exec`, terminal and
/// completed two days ago so a one-day archival moves it.
async fn make_terminal_v3_global_output(
    pool: &sqlx::PgPool,
    sm: &controller::secrets::SecretsManager,
    exec: Uuid,
    value: &serde_json::Value,
) -> Uuid {
    let (kid, ct, ver) = sm
        .encrypt_value_aad_v3(&serde_json::to_string(value).unwrap(), exec.as_bytes())
        .await
        .unwrap();
    assert_eq!(ver, 3);
    sqlx::query(
        "UPDATE workflow_executions SET output_data = NULL, output_data_enc = $1, \
         output_enc_key_id = $2, output_data_format = 3, status = 'completed', \
         completed_at = NOW() - INTERVAL '2 days' WHERE id = $3",
    )
    .bind(ct.as_slice())
    .bind(kid)
    .bind(exec)
    .execute(pool)
    .await
    .unwrap();
    kid
}

async fn archived_output_key(pool: &sqlx::PgPool, exec: Uuid) -> (i16, Uuid) {
    sqlx::query_as(
        "SELECT output_data_format, output_enc_key_id FROM workflow_executions_archive WHERE id=$1",
    )
    .bind(exec)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn archive_output_pending(sm: &controller::secrets::SecretsManager) -> i64 {
    sm.dek_migration_status()
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.table == "workflow_executions_archive.output")
        .map(|e| e.pending)
        .expect("dek_migration_status must report the archive tier")
}

#[tokio::test]
async fn archived_outputs_are_counted_and_re_keyed_onto_the_org_dek() {
    let (user, org, exec, sm, pool) = seed_running_execution("archsweep").await;
    let output = serde_json::json!({ "result": "archived-legacy-output" });
    let global_kid = make_terminal_v3_global_output(&pool, &sm, exec, &output).await;

    // Archive it through the production retention move.
    let moved = talos_advanced_repository::AdvancedRepository::new(pool.clone())
        .archive_executions(1, user)
        .await
        .unwrap();
    assert_eq!(moved, 1, "the terminal row must move into the archive");
    assert_eq!(
        archived_output_key(&pool, exec).await,
        (3, global_kid),
        "the move carries the ciphertext and its global key unchanged"
    );

    // Counted as pending on the archive tier.
    let before = archive_output_pending(&sm).await;
    assert!(before >= 1, "an archived global-DEK output is pending");

    let repo =
        talos_execution_repository::ExecutionRepository::with_encryption(pool.clone(), sm.clone());
    let stats = repo.re_encrypt_outputs_to_org().await.unwrap();
    assert_eq!(stats.failed, 0);
    assert!(
        stats.archive_re_encrypted >= 1,
        "the archived row is reported as re-keyed from the archive"
    );

    // v4 under the WORKFLOW's org DEK — the org the page selected, not a
    // live-row lookup (an archived row has none and would re-seal globally).
    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(archived_output_key(&pool, exec).await, (4, org_dek.id));
    assert_eq!(
        archive_output_pending(&sm).await,
        before - 1,
        "the status count drops by exactly the re-keyed row"
    );

    // Reads back through the archive read path.
    match repo.lookup_execution(exec, user).await.unwrap() {
        talos_execution_repository::ExecutionLookup::Archived { row, .. } => {
            assert_eq!(row.output_data, Some(output.clone()), "value survives");
        }
        other => panic!("execution must be Archived, got {other:?}"),
    }

    // A rotated org DEK leaves the archived row pending again; the sweep moves
    // it onto the new active key.
    let new_key = sm
        .rotate_dek_for_org(org, None)
        .await
        .unwrap()
        .expect("the org exists");
    assert!(archive_output_pending(&sm).await >= 1);
    let stats = repo.re_encrypt_outputs_to_org().await.unwrap();
    assert_eq!(stats.failed, 0);
    assert_eq!(archived_output_key(&pool, exec).await, (4, new_key));
    match repo.lookup_execution(exec, user).await.unwrap() {
        talos_execution_repository::ExecutionLookup::Archived { row, .. } => {
            assert_eq!(row.output_data, Some(output), "value survives the re-key");
        }
        other => panic!("execution must be Archived, got {other:?}"),
    }
}

#[tokio::test]
async fn output_sweep_pages_past_one_page_and_steps_over_an_unreadable_row() {
    let (user, org, first, sm, pool) = seed_running_execution("pagesweep").await;
    let (wf, actor): (Uuid, Uuid) =
        sqlx::query_as("SELECT workflow_id, actor_id FROM workflow_executions WHERE id = $1")
            .bind(first)
            .fetch_one(&pool)
            .await
            .unwrap();

    // One more pending row than a page holds.
    let n = talos_execution_repository::OUTPUT_SWEEP_PAGE as usize + 1;
    let mut execs = vec![first];
    for _ in 1..n {
        let e = Uuid::new_v4();
        insert_running_execution(&pool, e, wf, user, actor).await;
        execs.push(e);
    }
    for e in &execs {
        make_terminal_v3_global_output(&pool, &sm, *e, &serde_json::json!({ "n": e.to_string() }))
            .await;
    }
    // And a FULL PAGE of rows whose ciphertext cannot be opened. Each must be
    // counted as failed and stepped over: with fewer than a page of them the
    // keyset cursor is not load-bearing (the loop ends on a short page anyway),
    // so only a full page proves the sweep cannot re-read the same rows forever.
    let mut bad = Vec::new();
    let mut global_kid = Uuid::nil();
    for _ in 0..talos_execution_repository::OUTPUT_SWEEP_PAGE {
        let b = Uuid::new_v4();
        insert_running_execution(&pool, b, wf, user, actor).await;
        global_kid = make_terminal_v3_global_output(&pool, &sm, b, &serde_json::json!({})).await;
        bad.push(b);
    }
    sqlx::query(
        "UPDATE workflow_executions SET output_data_enc = '\\x00ff'::bytea WHERE id = ANY($1)",
    )
    .bind(&bad)
    .execute(&pool)
    .await
    .unwrap();

    // The sweep runs on its OWN thread, runtime, pool and SecretsManager. A
    // sweep that re-reads the same unreadable page forever must FAIL this test
    // rather than hang the binary: a timeout inside the test's runtime cannot
    // guarantee that, because dropping the runtime waits for the stuck task.
    let (tx, rx) = std::sync::mpsc::channel();
    let opts = (*pool.connect_options()).clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async move {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect_with(opts)
                .await?;
            let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone())?);
            sm.initialize().await?;
            talos_execution_repository::ExecutionRepository::with_encryption(pool, sm)
                .re_encrypt_outputs_to_org()
                .await
        });
        let _ = tx.send(result);
    });
    let outcome =
        tokio::task::spawn_blocking(move || rx.recv_timeout(std::time::Duration::from_secs(60)))
            .await
            .unwrap();
    // Record the unreadable rows' state NOW, then delete them BEFORE asserting:
    // the binary's tests share one database and every other test runs a
    // whole-table sweep, so a page of unreadable rows left behind by a failure
    // here would make those sweeps fail (or, under a cursor regression, spin)
    // instead of this test reporting the one defect.
    let untouched: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_executions \
         WHERE id = ANY($1) AND output_data_format = 3 AND output_enc_key_id = $2",
    )
    .bind(&bad)
    .bind(global_kid)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM workflow_executions WHERE id = ANY($1)")
        .bind(&bad)
        .execute(&pool)
        .await
        .unwrap();

    let stats = outcome.expect("the sweep must terminate").unwrap();
    assert!(stats.re_encrypted >= n as u64, "every page is swept");
    assert!(
        stats.failed >= bad.len() as u64,
        "every unreadable row is reported as failed"
    );
    assert_eq!(
        untouched,
        bad.len() as i64,
        "rows that cannot be opened are left as they were"
    );

    let org_dek = sm.get_active_dek_for_org(org).await.unwrap().unwrap();
    let left: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_executions \
         WHERE id = ANY($1) AND (output_data_format <> 4 OR output_enc_key_id <> $2)",
    )
    .bind(&execs)
    .bind(org_dek.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0, "no row past the first page is left behind");
}
