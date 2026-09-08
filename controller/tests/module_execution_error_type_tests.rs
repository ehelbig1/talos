//! `module_executions.error_type` must carry the CAUSE of an engine-recorded
//! failure — or nothing, never a guess.
//!
//! The column was writable from the day it existed and had five writers, none
//! of which covered the common case. `fail_execution` takes an `error_type`,
//! `timeout_execution` hardcodes `'timeout'`, the stuck sweep writes `'stuck'`
//! (relabelled `'ledger_unfinalized'` by migration 20260812120000), and four
//! integration dispatch paths pass `signing_error` / `nats_publish` /
//! `dlq_replay_dispatch`. A module that RAN and FAILED reaches none of them: it
//! is closed out by `ModuleExecutionStore::record_completed`, whose trait
//! signature has no `error_type` slot. Measured on the live dev ledger before
//! the fix: **59 of 59** `failed` rows NULL — beside 21 874 `timeout` rows that
//! did carry a value. `ModuleExecution.errorType` is a public GraphQL field
//! (`moduleExecutionHistory`), so a consumer saw null on exactly the status
//! where a cause matters, with nothing saying whether that meant
//! "unclassifiable" or "nobody ever wrote this".
//!
//! These tests drive the REAL production writer — `PostgresModuleExecutionStore`,
//! the only non-test `ModuleExecutionStore` impl in the workspace, reached
//! through the same trait method `ParallelWorkflowEngine::
//! finalize_module_execution_row` calls on every single-node, loop and pipeline
//! exit — against a real Postgres. The derivation is pure and unit-tested in
//! `talos_engine::module_error_type`; what only a round trip can prove is that
//! the derived value is BOUND and SURVIVES.
//!
//! # Which of these fail on pristine main, and which do not
//!
//! Stated rather than implied, because a test that passes on main is a
//! regression guard and not evidence the defect existed.
//!
//! * [`an_engine_recorded_failure_stores_its_cause`] and
//!   [`a_host_stamped_marker_reaches_the_column`] FAIL on main by assertion —
//!   main stores NULL. They compile there unchanged because this fix
//!   deliberately did not alter the trait signature.
//! * [`an_unclassifiable_failure_stores_null_not_a_guess`],
//!   [`a_diagnostic_appendix_cannot_manufacture_a_cause`] and
//!   [`a_completed_row_is_never_given_a_cause`] PASS on main — main writes NULL
//!   for everything, and NULL is also the right answer for all three. They
//!   exist because the interesting failure mode after this change is the
//!   opposite one: stamping a fall-through bucket on a message nobody
//!   classified. A wrong stored label is worse than an absent one, because a
//!   later reader cannot tell it from a real one.

mod common;

use talos_workflow_engine_core::ModuleExecutionStore;
use uuid::Uuid;

/// Seed the FK chain and open one `module_executions` row in `'running'` —
/// the state `record_started` leaves it in, and the only state
/// `record_completed`'s `WHERE status IN ('pending','running')` guard admits.
async fn seed_running_row(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@me-errtype.test"))
    .execute(pool)
    .await
    .expect("seed user");

    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("m-{module}"))
        .execute(pool)
        .await
        .expect("seed module");

    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user)
        .bind(format!("actor-{actor}"))
        .execute(pool)
        .await
        .expect("seed actor");

    let exec = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions \
         (id, module_id, user_id, actor_id, status, trigger_type) \
         VALUES ($1, $2, $3, $4, 'running', 'manual')",
    )
    .bind(exec)
    .bind(module)
    .bind(user)
    .bind(actor)
    .execute(pool)
    .await
    .expect("seed running module_execution");

    exec
}

/// Read back what an operator would see through
/// `ModuleExecution.errorType` / `.errorMessage`.
async fn read_back(
    pool: &sqlx::Pool<sqlx::Postgres>,
    exec: Uuid,
) -> (String, Option<String>, Option<String>) {
    sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
        "SELECT status, error_type, error_message FROM module_executions WHERE id = $1",
    )
    .bind(exec)
    .fetch_one(pool)
    .await
    .expect("read back the finalized row")
}

/// Finalize one seeded row through the production writer and hand back the
/// stored `(status, error_type, error_message)`.
async fn finalize(
    status: &str,
    error_message: Option<&str>,
) -> (String, Option<String>, Option<String>) {
    let (pool, _db) = common::isolated_db_pool().await;
    let exec = seed_running_row(&pool).await;

    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(pool.clone());
    store
        .record_completed(exec, status, &serde_json::Value::Null, None, error_message)
        .await
        .expect("record_completed");

    read_back(&pool, exec).await
}

/// THE REGRESSION. Verbatim from the live ledger — the single largest failure
/// message in the table (12 of 59 rows). Main stores NULL here.
#[tokio::test]
async fn an_engine_recorded_failure_stores_its_cause() {
    let observed = "Job failed after 1 attempts: execution timed out after 30 seconds";
    let (status, error_type, message) = finalize("failed", Some(observed)).await;

    assert_eq!(status, "failed");
    assert_eq!(
        error_type.as_deref(),
        Some("timeout"),
        "an engine-recorded failure must carry its cause. NULL here is the \
         pre-fix state: `record_completed` bound `error_message` and nothing \
         else, so every one of the 59 failed rows in the live ledger read as \
         unclassified through GraphQL's ModuleExecution.errorType"
    );
    assert!(
        message.as_deref().is_some_and(|m| m.contains("timed out")),
        "the label must sit beside the text it was derived from, not replace it"
    );
}

/// The host-stamped `[reason_class=…]` marker is the only AUTHORITATIVE
/// statement of cause in a worker failure string — everything else is a
/// substring guess at module prose. `tier1-egress` is chosen because no prose
/// gate can reach it: the message body renders as an opaque `networkerror`, so
/// a column reading `egress_tier_denied` can only have come from the marker.
///
/// This is the case that most needs the column. An actor's egress ceiling
/// refusing a destination is fixed on the ACTOR and by no module-level change;
/// unlabelled, it is indistinguishable from a DNS blip.
#[tokio::test]
async fn a_host_stamped_marker_reaches_the_column() {
    let observed = "Job failed after 1 attempts: execution failure: Component returned error: \
                    HTTP request failed: Error { code: 2, name: \"networkerror\", message: \"\" } \
                    [reason_class=tier1-egress]";
    let (_status, error_type, _message) = finalize("failed", Some(observed)).await;

    assert_eq!(
        error_type.as_deref(),
        Some("egress_tier_denied"),
        "the worker stamped the cause into the message and the column must \
         carry it. `network_error` here would mean the prose gate won over the \
         marker; NULL would mean the marker was never read"
    );
}

/// Verbatim from the live ledger (5 of 59 rows). A `result_nonce` that is too
/// old is a controller/worker clock-skew or backlog problem — it is not a
/// module fault at all, and the classifier has no bucket for it.
///
/// PASSES ON MAIN. Its job is the direction this change could newly get wrong:
/// the classifier's fall-through describes every unrecognised message as "an
/// unexpected runtime error occurred inside the module", which for this message
/// is false AND points at the wrong component. Stored, that is indistinguishable
/// from a real classification forever.
#[tokio::test]
async fn an_unclassifiable_failure_stores_null_not_a_guess() {
    let observed = "Job result signature verification failed: result_nonce is too old \
                    (715 s, max 300)";
    let (_status, error_type, message) = finalize("failed", Some(observed)).await;

    assert_eq!(
        error_type, None,
        "a message the classifier does not recognise must leave the column \
         NULL. A stored fall-through bucket cannot later be told apart from a \
         real classification"
    );
    assert!(
        message.is_some(),
        "refusing to LABEL the failure must not lose the failure text — the \
         message is what an operator reads when the label is absent"
    );
}

/// THE MEASURED HAZARD, at the column. Verbatim from the live ledger.
///
/// `talos-workflow-engine-nats` appends `" | diag: {…}"` — a JSON dump of the
/// job's SIGNED FIELD VALUES — to the retry-exhausted message (MCP-1212). That
/// dump contains the key `"timeout_ms"`, and every classifier gate below the
/// marker is a substring search, so the appendix trips the `timeout` gate on a
/// job whose SIGNATURE did not verify. Stored, that is a specific and
/// actionable instruction ("bump timeout_secs or split the work") about a
/// failure timeouts had no part in.
///
/// PASSES ON MAIN (main stores NULL for everything). It is here because the
/// same message is the one that most nearly made this change ship a lie.
#[tokio::test]
async fn a_diagnostic_appendix_cannot_manufacture_a_cause() {
    let observed = "Job failed after 1 attempts: signature verification failed | diag: \
        {\"actor_id\":\"4f14999a-2de3-412f-b0f2-a37859e77268\",\"allowed_hosts\":[],\
        \"expected_wasm_hash\":null,\"signature_byte_len\":64,\"timeout_ms\":120000,\
        \"verify_error\":\"job_nonce is too old (902 s, max 300)\"}";
    let (_status, error_type, _message) = finalize("failed", Some(observed)).await;

    assert_eq!(
        error_type, None,
        "a signature-verification failure must not be stored as 'timeout' \
         because the diagnostic dump of signed fields happened to contain a \
         key named timeout_ms"
    );
}

/// A success has no cause. Guarded on the STATUS rather than on the message
/// being absent, so a future caller that passes informational text alongside
/// `"completed"` cannot label a successful row.
///
/// PASSES ON MAIN.
#[tokio::test]
async fn a_completed_row_is_never_given_a_cause() {
    let (status, error_type, _message) =
        finalize("completed", Some("execution timed out after 30 seconds")).await;

    assert_eq!(status, "completed");
    assert_eq!(
        error_type, None,
        "a completed row must carry no error_type even when a message is \
         supplied alongside it"
    );
}

// ---------------------------------------------------------------------------
// 2026-09-08 — the two callers #744 did not reach
// ---------------------------------------------------------------------------
//
// #744 derived the cause at the ENGINE's finalizer. It left the OTHER writer,
// `ModuleExecutionService::fail_execution_from_worker`, taking whatever its two
// callers passed — and both passed `None` on the non-timeout path:
//
//   * `talos-webhooks/src/router.rs` finalizes a MODULE-bound webhook dispatch.
//     No engine is in that path at all, so nothing else ever closes the row and
//     every such failure stored NULL — #744's gap, one path over.
//   * `controller/src/bootstrap/background.rs`'s `talos.results.*` observer,
//     which stamped a hardcoded `"timeout"` for `JobStatus::TimedOut` and
//     nothing for a plain `Failed`.
//
// Both are LATENT on the reference fleet and that is stated rather than
// dressed up: measured 2026-09-08, `webhook_triggers` holds ONE row with
// `module_id IS NULL`, so the webhook module path has no live population; and
// the observer's own comment records that "every NATS-dispatched code path uses
// request-reply, so this subscriber is mostly dormant". What the fix buys is
// that the column's vocabulary has ONE home for every writer that can reach it.

/// The OTHER production writer must carry a derived cause through to the row.
///
/// This drives `fail_execution_from_worker` — the method both remaining callers
/// use — with exactly what those call sites now compute, and reads back what an
/// operator sees. It is a ROUND TRIP, not a re-derivation: the pure derivation
/// is unit-tested in `talos_engine::module_error_type`, and what only a real
/// Postgres can prove is that the value BINDS and SURVIVES this second
/// statement, whose `error_type = $2` sits in a different UPDATE from
/// `record_completed`'s `error_type = $8`.
#[tokio::test]
async fn the_worker_finalizer_stores_a_derived_cause() {
    let (pool, _db) = common::isolated_db_pool().await;
    let exec = seed_running_row(&pool).await;

    let observed = "execution failure: Component returned error: request timed out after 30s";
    let derived = talos_engine::module_error_type::derive_error_type("failed", Some(observed))
        .map(str::to_string);
    assert_eq!(
        derived.as_deref(),
        Some("timeout"),
        "control: the derivation itself must answer before the round trip can \
         say anything about binding"
    );

    let svc = talos_module_executions::ModuleExecutionService::new(
        pool.clone(),
        std::sync::Arc::new(talos_dlp_provider::DlpService::from_env()),
    );
    svc.fail_execution_from_worker(exec, observed.to_string(), derived, None)
        .await
        .expect("fail_execution_from_worker");

    let (status, error_type, message) = read_back(&pool, exec).await;
    assert_eq!(status, "failed");
    assert_eq!(
        error_type.as_deref(),
        Some("timeout"),
        "the derived cause must survive `fail_execution_from_worker`'s own \
         UPDATE. `None` here is the pre-fix state at both of its callers"
    );
    assert!(message.as_deref().is_some_and(|m| m.contains("timed out")));
}

/// The CONTROL for the test above: an unclassifiable message must still store
/// NULL through this writer, so the round trip cannot pass by stamping
/// something on everything.
#[tokio::test]
async fn the_worker_finalizer_stores_null_for_an_unclassifiable_message() {
    let (pool, _db) = common::isolated_db_pool().await;
    let exec = seed_running_row(&pool).await;

    let observed = "zzzz nothing here resembles a known cause";
    let derived = talos_engine::module_error_type::derive_error_type("failed", Some(observed))
        .map(str::to_string);
    assert_eq!(derived, None);

    let svc = talos_module_executions::ModuleExecutionService::new(
        pool.clone(),
        std::sync::Arc::new(talos_dlp_provider::DlpService::from_env()),
    );
    svc.fail_execution_from_worker(exec, observed.to_string(), derived, None)
        .await
        .expect("fail_execution_from_worker");

    let (_status, error_type, _message) = read_back(&pool, exec).await;
    assert_eq!(
        error_type, None,
        "a wrong stored label is worse than an absent one — once written it is \
         indistinguishable from a real one"
    );
}

/// The WIRING, which no round trip can see.
///
/// Both remaining call sites are unreachable from an integration test:
/// `background.rs` is `mod bootstrap` inside `main.rs` (bin-private), and the
/// webhook one needs a full module-bound webhook dispatch that this fleet has
/// no row for. So reverting either to `None` is behaviourally identical to
/// every test in the workspace — the shape checks 74b and 79b state as their
/// own limit, and the shape `task_supervision_wiring_tests` /
/// `push_channel_wiring_tests` answer by pinning the SOURCE.
///
/// Deliberately asserts on both the derivation AND the absence of the old
/// spellings, because a site that names the helper and then discards its answer
/// would satisfy a name-only pin.
#[test]
fn both_remaining_worker_finalizers_derive_their_cause() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");

    let webhooks = std::fs::read_to_string(root.join("talos-webhooks/src/router.rs"))
        .expect("read talos-webhooks/src/router.rs");
    assert!(
        webhooks.contains("module_error_type::derive_error_type(\"failed\", Some(&msg))"),
        "talos-webhooks' module-dispatch finalizer must derive `error_type` \
         from the same text it stores. Passing `None` again is the pre-fix \
         state and nothing else in this workspace can observe it"
    );

    let background = std::fs::read_to_string(root.join("controller/src/bootstrap/background.rs"))
        .expect("read controller/src/bootstrap/background.rs");
    assert!(
        background.contains("module_error_type::TIMEOUT_BUCKET"),
        "the job-result observer's TimedOut arm must name the shared constant, \
         not re-spell the bucket inline"
    );
    assert!(
        background.contains("module_error_type::derive_error_type("),
        "the job-result observer's plain-Failed arm must derive `error_type` \
         rather than store nothing"
    );
    assert!(
        !background.contains(".then_some(\"timeout\".to_string())"),
        "the pre-fix expression must be gone, not merely joined by a sibling: \
         a file that carries both is a file where the revert is one deletion"
    );
}
