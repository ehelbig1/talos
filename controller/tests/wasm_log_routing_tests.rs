//! Where a WASM log line lands — and what the writer reports when it lands
//! nowhere.
//!
//! Every `wasm.log.{execution_id}` line the worker publishes is routed by the
//! controller's subscriber into `workflow_execution_logs` (when the id names a
//! workflow execution) or `module_execution_logs` (when it names a module
//! execution). BOTH inserts are `WHERE EXISTS`-guarded, so an id that names
//! neither silently affects zero rows.
//!
//! For months that was not a hypothetical: loop-body iterations dispatched
//! with `job_id: None`, the dispatcher minted a UUID that existed in neither
//! table, and every log line from every Loop iteration — host diagnostics AND
//! the guest's own `logging::log` — was discarded. `add_log` returned `Ok(())`
//! regardless because it matched `Ok(_)` and never looked at `rows_affected`,
//! and `get_execution_logs` returns `[]` for empty, so a discarded-log
//! execution was byte-identical to a silent one.
//!
//! These tests exercise the REAL `add_log` against a REAL Postgres so the
//! `WHERE EXISTS` predicate is the thing under test — a mock cannot fail the
//! way the production statement failed. They cover both halves of the fix:
//! that a line for a recorded execution row lands AND is readable back, and
//! that a line for an unknown id is reported as `NoExecutionRow` rather than
//! as success.

mod common;

use std::sync::Arc;

use talos_module_executions::{LogLevel, LogWriteOutcome, ModuleExecutionService};
use uuid::Uuid;

struct Fixture {
    pool: sqlx::Pool<sqlx::Postgres>,
    service: ModuleExecutionService,
    user: Uuid,
    module: Uuid,
    actor: Uuid,
    _db: common::TestDb,
}

async fn fixture() -> Fixture {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(user)
    .bind(format!("{user}@wasm-log-routing.test"))
    .execute(&pool)
    .await
    .expect("seed user");

    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("m-{module}"))
        .execute(&pool)
        .await
        .expect("seed module");

    // actor_id is NOT NULL on module_executions post actor-universalization.
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("actor-{actor}"))
        .execute(&pool)
        .await
        .expect("seed actor");

    let service = ModuleExecutionService::new(
        pool.clone(),
        Arc::new(talos_dlp_provider::DlpService::from_env()),
    );
    Fixture {
        pool,
        service,
        user,
        module,
        actor,
        _db,
    }
}

impl Fixture {
    /// Insert a `module_executions` row — the shape
    /// `ModuleExecutionStore::record_started` produces for a dispatched node
    /// (and now, for every loop-body iteration).
    async fn seed_execution_row(&self) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO module_executions \
             (id, module_id, user_id, actor_id, status, trigger_type) \
             VALUES ($1, $2, $3, $4, 'running', 'webhook')",
        )
        .bind(id)
        .bind(self.module)
        .bind(self.user)
        .bind(self.actor)
        .execute(&self.pool)
        .await
        .expect("seed module_executions row");
        id
    }

    async fn log_row_count(&self, execution_id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM module_execution_logs WHERE execution_id = $1")
            .bind(execution_id)
            .fetch_one(&self.pool)
            .await
            .expect("count log rows")
    }
}

/// The happy path: a line addressed to a REAL execution row is inserted, is
/// reported as `Inserted`, and reads back.
#[tokio::test]
async fn log_for_a_recorded_execution_is_inserted_and_readable() {
    let f = fixture().await;
    let exec_id = f.seed_execution_row().await;

    let outcome = f
        .service
        .add_log(
            exec_id,
            LogLevel::Info,
            "fetched 3 items".to_string(),
            Some(serde_json::json!({ "count": 3 })),
        )
        .await
        .expect("add_log must not error on the happy path");

    assert_eq!(
        outcome,
        LogWriteOutcome::Inserted,
        "a line for an existing execution row must report as inserted"
    );
    assert!(outcome.is_inserted());
    assert!(
        !outcome.is_orphaned(),
        "the orphan warn must NOT fire on the normal path"
    );
    assert_eq!(f.log_row_count(exec_id).await, 1);

    let logs = f
        .service
        .get_execution_logs(exec_id, f.user)
        .await
        .expect("logs readable");
    assert_eq!(logs.len(), 1);
    assert!(logs[0].message.contains("fetched 3 items"));
}

/// THE regression. A line addressed to an id with no `module_executions` row
/// is DISCARDED by the `WHERE EXISTS` guard. `add_log` must say so instead of
/// returning a bare success — the silence is what hid the loop-body log drop.
#[tokio::test]
async fn log_for_an_unknown_execution_id_reports_no_execution_row() {
    let f = fixture().await;
    // The id the pre-fix loop path effectively used: a fresh UUID that no
    // INSERT ever created a row for.
    let orphan_id = Uuid::new_v4();

    let outcome = f
        .service
        .add_log(
            orphan_id,
            LogLevel::Warn,
            "[host:dns-resolution-failed] hostname resolution failed".to_string(),
            None,
        )
        .await
        .expect("a dropped log is not an error — it must not fail the execution");

    assert_eq!(
        outcome,
        LogWriteOutcome::NoExecutionRow,
        "swallowing rows_affected here is exactly the bug: `Ok(())` for a line that was thrown \
         away made every Loop iteration's logs vanish without a trace"
    );
    assert!(outcome.is_orphaned(), "this is what drives the orphan warn");
    assert!(!outcome.is_inserted());
    assert_eq!(
        f.log_row_count(orphan_id).await,
        0,
        "nothing was written — the outcome is not merely pessimistic"
    );

    // And the surface an operator would consult confirms the ambiguity the
    // warn exists to resolve: a discarded-log execution is indistinguishable
    // from a silent one from here.
    let logs = f
        .service
        .get_execution_logs(orphan_id, f.user)
        .await
        .expect("read");
    assert!(
        logs.is_empty(),
        "`[]` — identical to an execution that genuinely logged nothing, which is why the \
         WRITER has to be the one that reports the drop"
    );
}

/// `add_log_best_effort` — the wrapper the WASM-log subscriber actually calls
/// — must propagate the same distinction, or the caller cannot warn.
#[tokio::test]
async fn best_effort_wrapper_propagates_the_outcome() {
    let f = fixture().await;
    let real = f.seed_execution_row().await;

    assert_eq!(
        f.service
            .add_log_best_effort(real, LogLevel::Info, "hello".to_string(), None)
            .await,
        LogWriteOutcome::Inserted
    );
    assert_eq!(
        f.service
            .add_log_best_effort(Uuid::new_v4(), LogLevel::Info, "hello".to_string(), None)
            .await,
        LogWriteOutcome::NoExecutionRow
    );
}

/// End-to-end for D1's payoff: a row created the way the loop path now
/// creates one (`PostgresModuleExecutionStore::record_started`) makes the
/// persist predicate match, so the iteration's logs survive. Before D1 the
/// loop's job id had no row and this path stored nothing.
#[tokio::test]
async fn a_row_recorded_by_the_execution_store_makes_loop_logs_persist() {
    use talos_workflow_engine_core::{ExecutionStartedContext, ModuleExecutionStore};

    let f = fixture().await;

    // A parent workflow execution, as a loop iteration always has.
    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, name, user_id, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'test-module', '{}'::jsonb)",
    )
    .bind(workflow)
    .bind(format!("wf-{workflow}"))
    .bind(f.user)
    .execute(&f.pool)
    .await
    .expect("seed workflow");
    let wf_exec = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, actor_id) \
         VALUES ($1, $2, $3, 'running', $4)",
    )
    .bind(wf_exec)
    .bind(workflow)
    .bind(f.user)
    .bind(f.actor)
    .execute(&f.pool)
    .await
    .expect("seed workflow_execution");

    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(f.pool.clone());
    // The id the loop body now dispatches under.
    let iter_exec_id = Uuid::new_v4();
    store
        .record_started(ExecutionStartedContext {
            id: iter_exec_id,
            module_id: f.module,
            user_id: f.user,
            workflow_execution_id: wf_exec,
            input: &serde_json::json!({ "iteration": 0 }),
            trigger_type: "webhook",
            race_safe_status: true,
            actor_id: Some(f.actor),
        })
        .await
        .expect("record_started must succeed for a loop iteration");

    // Now the worker's log line for that job id has somewhere to land.
    let outcome = f
        .service
        .add_log(
            iter_exec_id,
            LogLevel::Info,
            "loop body says hello".to_string(),
            None,
        )
        .await
        .expect("add_log");
    assert_eq!(
        outcome,
        LogWriteOutcome::Inserted,
        "with a real row the loop iteration's logs persist — the whole point of D1"
    );

    // And they are reachable through the workflow-scoped tail the operator
    // uses, via module_execution_logs → module_executions.workflow_execution_id.
    let joined: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM module_execution_logs mel \
         JOIN module_executions me ON me.id = mel.execution_id \
         WHERE me.workflow_execution_id = $1",
    )
    .bind(wf_exec)
    .fetch_one(&f.pool)
    .await
    .expect("join count");
    assert_eq!(
        joined, 1,
        "the line must be reachable from the PARENT execution — an operator tails the workflow, \
         not the iteration"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// The webhook half of the same family.
//
// A webhook-dispatched module job carries `job_id` as BOTH the job id and the
// execution id, so the `module_executions` row must exist before the job is
// published or every `wasm.log.{job_id}` line hits the same `WHERE EXISTS`
// guard and is discarded. Two paths dispatch such jobs:
//   * the LIVE delivery path — it inserted the row but only `tracing::error!`d
//     on failure and dispatched anyway, so any DB blip produced an invisible
//     execution;
//   * the DLQ REPLAY path — it never inserted a row at all, so 100% of
//     replayed module deliveries were orphaned, on the one path an operator
//     reaches for *because* they are debugging.
// Both now go through `talos_webhooks::insert_webhook_module_execution`, and
// these tests drive that exact function against a real Postgres.
// ───────────────────────────────────────────────────────────────────────────

fn secrets_manager(pool: &sqlx::Pool<sqlx::Postgres>) -> Arc<controller::secrets::SecretsManager> {
    Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("SecretsManager"))
}

/// The fix, end to end: the row the webhook helper writes is the one the log
/// router needs. Mutation-resistant — the same assertion is pointed at an
/// UNRECORDED uuid to prove it is not merely asserting `is_ok()`.
#[tokio::test]
async fn webhook_dispatch_row_makes_its_logs_land() {
    let f = fixture().await;
    let sm = secrets_manager(&f.pool);
    let job_id = Uuid::new_v4();

    talos_webhooks::insert_webhook_module_execution(
        &f.pool,
        &sm,
        job_id,
        f.module,
        f.user,
        &serde_json::json!({ "action": "opened", "number": 7 }),
        Some(f.actor),
    )
    .await
    .expect("the webhook tracking row must insert");

    let outcome = f
        .service
        .add_log(
            job_id,
            LogLevel::Info,
            "webhook module says hello".to_string(),
            None,
        )
        .await
        .expect("add_log");
    assert_eq!(
        outcome,
        LogWriteOutcome::Inserted,
        "a job dispatched under this id can be tailed — the DLQ replay path had no row at all, \
         so this was NoExecutionRow for every replayed delivery"
    );

    // The control: an id no INSERT ever created — same call, same table, and
    // it must NOT report Inserted. Without this, the assertion above would
    // still pass if `add_log` had been weakened to always report success.
    let never_recorded = Uuid::new_v4();
    assert_eq!(
        f.service
            .add_log(never_recorded, LogLevel::Info, "orphan".to_string(), None)
            .await
            .expect("add_log"),
        LogWriteOutcome::NoExecutionRow,
        "the positive assertion above is only meaningful if an unrecorded id still fails"
    );

    assert_eq!(f.log_row_count(job_id).await, 1);
    assert_eq!(f.log_row_count(never_recorded).await, 0);
}

/// Data-at-rest, ENCRYPTING branch: with a DEK provisioned (the production
/// state), the webhook body must land as ciphertext only. Webhook bodies
/// routinely carry secret-shaped values — provider callbacks echo bearer
/// tokens — so a refactor that always bound `input_data` would be a silent
/// regression no shape test catches.
#[tokio::test]
async fn webhook_row_stores_ciphertext_when_encryption_is_available() {
    let f = fixture().await;
    let sm = secrets_manager(&f.pool);
    sm.initialize().await.expect("provision the global DEK");
    let job_id = Uuid::new_v4();

    talos_webhooks::insert_webhook_module_execution(
        &f.pool,
        &sm,
        job_id,
        f.module,
        f.user,
        &serde_json::json!({ "token": "sk-live-should-never-be-queryable" }),
        Some(f.actor),
    )
    .await
    .expect("insert");

    let (pt, ct, fmt): (Option<serde_json::Value>, Option<Vec<u8>>, Option<i16>) = sqlx::query_as(
        "SELECT input_data, input_data_enc, payload_format FROM module_executions WHERE id = $1",
    )
    .bind(job_id)
    .fetch_one(&f.pool)
    .await
    .expect("read back the row");

    assert!(
        pt.is_none(),
        "input_data must stay NULL while encryption succeeds — operators querying this column \
         must not be able to read the webhook body"
    );
    let ct = ct.expect("ciphertext must be present");
    assert!(!ct.is_empty());
    assert!(
        !String::from_utf8_lossy(&ct).contains("sk-live-should-never-be-queryable"),
        "the stored bytes must not contain the plaintext"
    );
    assert!(
        fmt.unwrap_or(0) > 0,
        "an encrypted row must record its AEAD format version"
    );
}

/// Data-at-rest, FALLBACK branch: when encryption is unavailable (KMS outage,
/// DEK rotation race, an un-initialized manager — the state of this fixture
/// before `initialize()`), the helper falls back to plaintext in `input_data`
/// — but DLP-REDACTED first (MCP-987). Preserving BOTH branches through the
/// extraction is the security invariant; a helper that dropped the redaction
/// would look fine in the happy-path test above and quietly land raw tokens in
/// a queryable column exactly when things are already going wrong.
#[tokio::test]
async fn webhook_row_redacts_the_plaintext_fallback() {
    let f = fixture().await;
    // Deliberately NOT initialized: no active DEK → encrypt_payload_bundle errs.
    let sm = secrets_manager(&f.pool);
    let job_id = Uuid::new_v4();

    talos_webhooks::insert_webhook_module_execution(
        &f.pool,
        &sm,
        job_id,
        f.module,
        f.user,
        &serde_json::json!({
            "api_key": "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "note": "keep me"
        }),
        Some(f.actor),
    )
    .await
    .expect("an encryption failure must NOT fail the insert — only the INSERT failing is fatal");

    let (pt, ct): (Option<serde_json::Value>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT input_data, input_data_enc FROM module_executions WHERE id = $1")
            .bind(job_id)
            .fetch_one(&f.pool)
            .await
            .expect("read back");

    assert!(ct.is_none(), "nothing was encrypted on this branch");
    let pt = pt.expect("the fallback stores the payload as plaintext");
    let rendered = pt.to_string();
    assert!(
        !rendered.contains("sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        "the secret-shaped value must be DLP-redacted before it reaches a queryable column; \
         got: {rendered}"
    );
    assert!(
        rendered.contains("keep me"),
        "redaction must not gut the payload — the non-secret field survives"
    );
}

/// `ON CONFLICT DO NOTHING` is load-bearing: an operator may replay the same
/// DLQ entry twice, and a second insert under a colliding id must not turn a
/// dispatch into an error.
#[tokio::test]
async fn webhook_row_insert_is_idempotent() {
    let f = fixture().await;
    let sm = secrets_manager(&f.pool);
    let job_id = Uuid::new_v4();
    let payload = serde_json::json!({ "action": "reopened" });

    for attempt in 1..=2 {
        talos_webhooks::insert_webhook_module_execution(
            &f.pool,
            &sm,
            job_id,
            f.module,
            f.user,
            &payload,
            Some(f.actor),
        )
        .await
        .unwrap_or_else(|e| panic!("insert attempt {attempt} must succeed: {e}"));
    }

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM module_executions WHERE id = $1")
        .bind(job_id)
        .fetch_one(&f.pool)
        .await
        .expect("count");
    assert_eq!(
        rows, 1,
        "the second insert must be a no-op, not a duplicate"
    );
}

/// Tenancy: the row is bound to the user the trigger names. A helper that
/// defaulted the user (the class the engine's `unwrap_or_else(Uuid::new_v4)`
/// was misread as) would produce a row that violates the `users` FK — or worse,
/// attributes the execution to nobody.
#[tokio::test]
async fn webhook_row_is_bound_to_the_trigger_user_and_actor() {
    let f = fixture().await;
    let sm = secrets_manager(&f.pool);
    let job_id = Uuid::new_v4();

    talos_webhooks::insert_webhook_module_execution(
        &f.pool,
        &sm,
        job_id,
        f.module,
        f.user,
        &serde_json::json!({}),
        Some(f.actor),
    )
    .await
    .expect("insert");

    let (uid, aid, status, trigger_type): (Uuid, Option<Uuid>, String, Option<String>) =
        sqlx::query_as(
            "SELECT user_id, actor_id, status, trigger_type FROM module_executions WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(&f.pool)
        .await
        .expect("read back");

    assert_eq!(uid, f.user);
    assert_eq!(aid, Some(f.actor));
    assert_eq!(status, "running");
    assert_eq!(trigger_type.as_deref(), Some("webhook"));

    // And an unknown user must be refused by the FK rather than silently
    // landing an unattributable row.
    let err = talos_webhooks::insert_webhook_module_execution(
        &f.pool,
        &sm,
        Uuid::new_v4(),
        f.module,
        Uuid::new_v4(),
        &serde_json::json!({}),
        Some(f.actor),
    )
    .await;
    assert!(
        err.is_err(),
        "a row for a non-existent user must fail loudly — the caller now stops the dispatch on it"
    );
}
