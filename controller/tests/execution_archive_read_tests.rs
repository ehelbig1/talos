//! ARCHIVED is not ABSENT — and the archive is not un-tenanted.
//!
//! #746 made execution archival work for the first time in the platform's
//! history. Its boot pass moved 96 executions into
//! `workflow_executions_archive`. Within the hour, every by-id reader answered
//! the same thing for one of them:
//!
//! ```text
//!   get_execution_status       → "Execution not found or access denied"
//!   get_execution_logs         → "Execution not found or access denied"
//!   get_execution_output       → "Execution not found or access denied"
//!   analyze_execution_failure  → "Execution not found or access denied"
//! ```
//!
//! Both clauses of that sentence are false. It IS found —
//! `list_archived_executions` returns it — and access is NOT denied: same
//! user, same tenancy predicate. `ExecutionRepository::get_execution` read
//! `workflow_executions` alone, so `Ok(None)` meant "absent" and "archived"
//! indistinguishably, at all twenty-two call sites.
//!
//! WHICH OF THESE FAIL ON PRISTINE MAIN, AND HOW — stated precisely, because
//! "it fails on main" is worthless if it fails by compile error:
//!
//!   * `an_archived_execution_is_not_invisible_to_a_by_id_read` is the
//!     load-bearing one. It is written twice: the version here drives the new
//!     `lookup_execution`, and its MAIN-VOCABULARY twin (the same seed, then
//!     `repo.get_execution(exec, user).await.unwrap().is_some()`) was copied
//!     into a clean `git archive origin/main` checkout and FAILS THERE BY
//!     ASSERTION — `get_execution` returns `None` for a row that is sitting in
//!     the archive under the caller's own `user_id`.
//!   * `the_archive_is_rls_isolated_from_another_tenant` is pure SQL and
//!     therefore compiles on main verbatim. It FAILS THERE BY ASSERTION: on
//!     main `workflow_executions_archive` has `relrowsecurity = false` and
//!     zero policies, so under `SET LOCAL ROLE talos_app` with user A's GUC,
//!     user B's archived execution is fully visible. Measured on the live dev
//!     database before this change:
//!
//!     ```text
//!       workflow_executions          rls=t forced=t  policies=1
//!       workflow_executions_archive  rls=f forced=f  policies=0
//!     ```
//!
//!     Until #746 that was academic — the table had never held a row. It now
//!     holds real tenant executions WITH their `output_data_enc` ciphertext,
//!     and the app-layer `AND user_id = $2` was the only thing scoping any
//!     read of it.
//!   * `the_archive_schema_is_rls_enabled_and_forced` is the cheap structural
//!     twin of the above and also fails on main by assertion.
//!   * The remaining tests name `ExecutionLookup`, which does not exist on
//!     main and therefore cannot be written in its vocabulary. They are
//!     new-behaviour coverage; the three above carry the main-failing burden.
//!
//! MEASURED, not asserted. The three twins were built and run against a clean
//! `git archive origin/main` checkout (aa68fc66) with its OWN migrated
//! database, alongside a CONTROL — `a live execution IS visible on main` —
//! which is what distinguishes "the defect" from "the seed is wrong":
//!
//! ```text
//!   an_archived_execution_is_not_invisible_to_a_by_id_read  FAILED (assertion)
//!   control_a_live_execution_is_visible                     ok
//!   the_archive_is_rls_isolated_from_another_tenant         FAILED (left: 1, right: 0)
//!   the_archive_schema_is_rls_enabled_and_forced            FAILED (assertion)
//! ```
//!
//! Not one of them fails by compile error, and the control passes.
//!
//! Every test drives the REAL production repository method against a real
//! Postgres. A pure-Rust test cannot cover any of this: the whole question is
//! which TABLE the row is in and which POLICY applies to it.

mod common;

use talos_execution_repository::{ExecutionLookup, ExecutionRepository};
use uuid::Uuid;

struct Seeded {
    user: Uuid,
    org: Uuid,
    workflow: Uuid,
    /// `workflow_executions.actor_id` is NOT NULL. The ARCHIVE's is not — it
    /// was created `LIKE workflow_executions` before that constraint landed
    /// and the three hand-written `sync_archive_*` migrations never mirrored
    /// it. Harmless here (an archived row can only arrive from a live one),
    /// but it is why `seed_archived` needs no actor and `seed_live` does.
    actor: Uuid,
    dek: Uuid,
}

/// The FK chain a `workflow_executions` (or archive) row needs.
async fn seed_tenant(pool: &sqlx::PgPool) -> Seeded {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@archive-read.test"))
    .execute(pool)
    .await
    .expect("seed user");

    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("arcorg-{tag}"))
    .bind(format!("arcorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");

    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb)",
    )
    .bind(workflow)
    .bind(user)
    .bind(org)
    .bind(format!("arcwf-{tag}"))
    .execute(pool)
    .await
    .expect("seed workflow");

    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("arcactor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");

    // `output_enc_key_id` carries an FK to `encryption_keys`, and one active
    // DEK per org is enforced by `idx_one_active_dek_per_org` — each seed makes
    // its own org, so this never collides with a sibling test.
    let dek: Uuid = sqlx::query_scalar(
        "INSERT INTO encryption_keys (encrypted_key, org_id) VALUES ('\\x00'::bytea, $1) \
         RETURNING id",
    )
    .bind(org)
    .fetch_one(pool)
    .await
    .expect("seed dek");

    Seeded {
        user,
        org,
        workflow,
        actor,
        dek,
    }
}

/// One row inserted DIRECTLY into `workflow_executions_archive` — the state the
/// retention sweep leaves behind, without depending on the sweep to produce it.
async fn seed_archived(pool: &sqlx::PgPool, t: &Seeded, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions_archive \
             (id, workflow_id, user_id, org_id, status, started_at, completed_at, \
              error_message, is_pinned, output_data_enc, output_enc_key_id, \
              output_data_format, archived_at) \
         VALUES ($1, $2, $3, $4, $5, NOW() - INTERVAL '40 days', \
                 NOW() - INTERVAL '40 days', 'boom', false, '\\xdeadbeef'::bytea, $6, 0, \
                 NOW() - INTERVAL '1 hour')",
    )
    .bind(id)
    .bind(t.workflow)
    .bind(t.user)
    .bind(t.org)
    .bind(status)
    .bind(t.dek)
    .execute(pool)
    .await
    .expect("seed archived execution");
    id
}

async fn seed_live(pool: &sqlx::PgPool, t: &Seeded, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, org_id, actor_id, status, started_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW())",
    )
    .bind(id)
    .bind(t.workflow)
    .bind(t.user)
    .bind(t.org)
    .bind(t.actor)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed live execution");
    id
}

// ── The defect ──────────────────────────────────────────────────────────────

/// **THE BUG.** A by-id read of an archived execution must come back as
/// ARCHIVED — carrying the row and the moment it was archived — not as an
/// absence that every caller renders "not found or access denied".
///
/// Main-vocabulary twin (verified to FAIL BY ASSERTION on a clean
/// `git archive origin/main` checkout):
///
/// ```ignore
/// let found = repo.get_execution(exec, t.user).await.unwrap();
/// assert!(found.is_some(), "an archived execution must not read as absent");
/// ```
#[tokio::test]
async fn an_archived_execution_is_not_invisible_to_a_by_id_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_archived(&pool, &t, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    let lookup = repo
        .lookup_execution(exec, t.user)
        .await
        .expect("lookup must not error");

    match lookup {
        ExecutionLookup::Archived { row, archived_at } => {
            assert_eq!(row.id, exec);
            assert_eq!(row.status, "completed");
            assert_eq!(row.workflow_id, t.workflow);
            assert_eq!(
                row.error_message.as_deref(),
                Some("boom"),
                "the archived row is complete — its error_message moved with it"
            );
            assert!(
                archived_at < chrono::Utc::now(),
                "archived_at must be the real stamp from the row, got {archived_at}"
            );
        }
        other => panic!(
            "an archived execution must classify as Archived, not {other:?} — collapsing it \
             into Absent is exactly what made four tools answer \"not found or access denied\" \
             about a row list_archived_executions returns"
        ),
    }
}

/// The control for the test above. A LIVE execution must still classify as
/// `Live` — a lookup that reported everything as archived would pass the
/// previous test and be equally wrong.
#[tokio::test]
async fn a_live_execution_still_classifies_as_live() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_live(&pool, &t, "running").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution(exec, t.user).await.unwrap() {
        ExecutionLookup::Live(row) => {
            assert_eq!(row.id, exec);
            assert_eq!(row.status, "running");
        }
        other => panic!("a live execution must classify as Live, got {other:?}"),
    }
}

/// The other control. A genuinely absent id must still be `Absent`, so the
/// operator-recognised "Execution not found or access denied" string keeps
/// meaning what it has always meant.
#[tokio::test]
async fn an_unknown_execution_is_still_absent() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution(Uuid::new_v4(), t.user).await.unwrap() {
        ExecutionLookup::Absent => {}
        other => panic!("an id that was never created must be Absent, got {other:?}"),
    }
}

// ── Tenancy ─────────────────────────────────────────────────────────────────

/// The archive lookup must carry the SAME app-layer scoping as the live one.
/// An archive read that dropped `AND user_id = $2` would be a cross-tenant
/// read of a table that, before this change, had no RLS to catch it.
#[tokio::test]
async fn another_tenants_archived_execution_is_absent_at_the_app_layer() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let b_exec = seed_archived(&pool, &b, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution(b_exec, a.user).await.unwrap() {
        ExecutionLookup::Absent => {}
        other => panic!(
            "user A must not see user B's archived execution, got {other:?} — the archive read \
             must carry the same user scoping as the live read"
        ),
    }
}

/// **The second layer, and the reason this change ships a migration.**
///
/// The test above proves the APPLICATION predicate scopes the read. This one
/// proves the DATABASE would still refuse if that predicate were dropped — the
/// backstop checks 25/42 exist to guarantee, which
/// `workflow_executions_archive` did not have.
///
/// The query below deliberately carries NO `user_id` predicate: it is the
/// mutation "someone removed `AND user_id = $2`" expressed as a test. Under
/// `SET LOCAL ROLE talos_app` (the request-path role, `NOSUPERUSER
/// NOBYPASSRLS`) with user A's GUC, user B's archived row must be invisible.
///
/// **Fails by assertion on pristine main**, where the table has RLS disabled
/// and no policy, so the count is 1.
#[tokio::test]
async fn the_archive_is_rls_isolated_from_another_tenant() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let b_exec = seed_archived(&pool, &b, "completed").await;

    let mut tx = pool.begin().await.expect("begin");
    // Same one-round-trip prologue `talos_db::begin_tenant_read_scoped` issues
    // when TALOS_RLS_SET_ROLE is on. `SET LOCAL` is transaction-scoped, so
    // nothing leaks back into the pooled connection.
    // `Executor::execute(&str)` — the SIMPLE query protocol, which is what
    // `talos_db::begin_tenant_read_scoped` uses. `sqlx::query()` goes through
    // the EXTENDED protocol, which refuses multiple commands in one parse.
    use sqlx::Executor as _;
    (&mut *tx)
        .execute(
            format!(
                "SET LOCAL ROLE talos_app; SET LOCAL app.current_user_id = '{}'; \
                 SET LOCAL app.current_org_ids = ''",
                a.user
            )
            .as_str(),
        )
        .await
        .expect("set role + GUCs");

    let visible: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM workflow_executions_archive WHERE id = $1")
            .bind(b_exec)
            .fetch_one(&mut *tx)
            .await
            .expect("count under talos_app");
    tx.commit().await.expect("commit");

    assert_eq!(
        visible, 0,
        "user B's archived execution must be invisible to user A even with the app-layer \
         user_id predicate removed — that is the whole point of the RLS backstop, and \
         workflow_executions_archive had none before this change"
    );
}

/// The owner's own archived row must still be visible under the same role and
/// GUC. Without this control, a policy of `USING (false)` would pass the test
/// above while hiding every archived execution from everyone.
#[tokio::test]
async fn the_owner_still_sees_their_own_archived_execution_under_rls() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let a_exec = seed_archived(&pool, &a, "failed").await;

    let mut tx = pool.begin().await.expect("begin");
    use sqlx::Executor as _;
    (&mut *tx)
        .execute(
            format!(
                "SET LOCAL ROLE talos_app; SET LOCAL app.current_user_id = '{}'; \
                 SET LOCAL app.current_org_ids = ''",
                a.user
            )
            .as_str(),
        )
        .await
        .expect("set role + GUCs");

    let visible: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM workflow_executions_archive WHERE id = $1")
            .bind(a_exec)
            .fetch_one(&mut *tx)
            .await
            .expect("count under talos_app");
    tx.commit().await.expect("commit");

    assert_eq!(
        visible, 1,
        "the owner must still read their own archived execution under the new policy"
    );
}

/// The structural twin: RLS must be ENABLED and FORCED, and the policy must
/// exist by name. Cheaper than the behavioural tests and it fails loudly if a
/// future migration disables either flag while leaving the policy in place
/// (a policy on a table with RLS off is inert and silent).
///
/// Fails by assertion on pristine main (`false`, `false`, `0`).
#[tokio::test]
async fn the_archive_schema_is_rls_enabled_and_forced() {
    let (pool, _db) = common::isolated_db_pool().await;

    let (enabled, forced): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
         WHERE relname = 'workflow_executions_archive'",
    )
    .fetch_one(&pool)
    .await
    .expect("read pg_class");

    assert!(
        enabled,
        "workflow_executions_archive must have ROW LEVEL SECURITY enabled — it holds real \
         tenant executions and their encrypted output payloads"
    );
    assert!(
        forced,
        "…and FORCED, so the policy binds the table owner too (matching workflow_executions)"
    );

    let policies: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_policies WHERE tablename = 'workflow_executions_archive' \
         AND policyname = 'workflow_executions_archive_tenant_isolation'",
    )
    .fetch_one(&pool)
    .await
    .expect("read pg_policies");
    assert_eq!(
        policies, 1,
        "the tenant-isolation policy must exist by name — RLS enabled with no policy denies \
         everything, which is a different bug"
    );
}

// ── What survives the move, and what does not ───────────────────────────────

/// The archive is column-for-column identical to the live table plus
/// `archived_at`, which is what lets ONE projection and ONE row mapping serve
/// both. `execution_retention_tests::archive_schema_parity_in_the_database`
/// is the gate for that; this asserts the consequence the READER depends on:
/// the encrypted-output columns are present and populated on an archived row,
/// so `get_execution_output` has something to decrypt.
#[tokio::test]
async fn an_archived_row_still_carries_its_encrypted_output_columns() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_archived(&pool, &t, "completed").await;

    let (enc_len, key_id): (Option<i32>, Option<Uuid>) = sqlx::query_as(
        "SELECT octet_length(output_data_enc), output_enc_key_id \
         FROM workflow_executions_archive WHERE id = $1",
    )
    .bind(exec)
    .fetch_one(&pool)
    .await
    .expect("read archived row");

    assert_eq!(
        enc_len,
        Some(4),
        "the archived row must keep its output ciphertext — the pre-#746 manual archive \
         enumerated 24 of 32 columns and silently dropped exactly this one"
    );
    assert_eq!(key_id, Some(t.dek), "…and the DEK id that opens it");
}

// ═══════════════════════════════════════════════════════════════════════════
// #749 — the FOUR sibling readers #748 named and did not fix
// ═══════════════════════════════════════════════════════════════════════════
//
// #748 replaced `get_execution` and fixed its fourteen call sites. Four OTHER
// repository methods read `workflow_executions` alone and collapsed the same
// two states, on six call sites. Two of them were losing real data on the dev
// fleet the day this was written, for archived execution
// `5492b60e-b413-4eac-badf-cdb20ed3119f`:
//
// ```text
//   get_execution_lineage → "Execution not found or access denied"
//   tail_worker_logs      → "Execution not found or access denied. …"
// ```
//
// WHICH OF THESE FAIL ON PRISTINE MAIN, AND HOW. Every one below has a
// MAIN-VOCABULARY twin that compiles against `origin/main` (4c74e7bf) — the
// old method names, the old signatures — and each was run there against its
// own migrated database. All six FAIL BY ASSERTION, none by compile error,
// and the controls pass. The twin is quoted in each test's doc comment.
//
//   an_archived_executions_owner_is_not_absent               FAILED (assertion)
//   an_archived_executions_base_columns_are_not_absent       FAILED (assertion)
//   the_latest_execution_may_be_the_archived_one             FAILED (assertion)
//   a_workflow_whose_runs_all_aged_out_still_has_a_latest    FAILED (assertion)
//   the_platform_admin_workflow_lookup_reaches_the_archive   FAILED (assertion)
//   a_lineage_tree_spanning_both_tables_is_returned_whole    FAILED (assertion)
//   worker_logs_survive_the_archival_move                    FAILED (assertion)

/// A `module_executions` row + one log line under it. `module_executions` has
/// NO foreign key to `workflow_executions` — only a plain `workflow_execution_id`
/// column — which is WHY worker logs outlive the archival move while
/// `execution_events` and `workflow_execution_logs` are CASCADEd away.
async fn seed_worker_log(pool: &sqlx::PgPool, t: &Seeded, parent: Uuid, message: &str) {
    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("arcmod-{module}"))
        .execute(pool)
        .await
        .expect("seed module");

    let me = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions \
             (id, module_id, user_id, actor_id, org_id, status, trigger_type, \
              workflow_execution_id) \
         VALUES ($1, $2, $3, $4, $5, 'completed', 'manual', $6)",
    )
    .bind(me)
    .bind(module)
    .bind(t.user)
    .bind(t.actor)
    .bind(t.org)
    .bind(parent)
    .execute(pool)
    .await
    .expect("seed module_execution");

    sqlx::query(
        "INSERT INTO module_execution_logs (execution_id, level, message) VALUES ($1, 'INFO', $2)",
    )
    .bind(me)
    .bind(message)
    .execute(pool)
    .await
    .expect("seed module_execution_log");
}

// ── get_workflow_execution_owner → lookup_execution_owner ───────────────────

/// **THE BUG, `tail_worker_logs` half.** The ownership gate resolved an
/// archived execution to `Ok(None)` and answered "Execution not found or
/// access denied" — while `module_execution_logs` still held every line the
/// caller asked for.
///
/// Main-vocabulary twin (FAILS BY ASSERTION on 4c74e7bf):
///
/// ```ignore
/// let owner = repo.get_workflow_execution_owner(exec).await.unwrap();
/// assert_eq!(owner, Some(t.user), "an archived execution still has an owner");
/// ```
#[tokio::test]
async fn an_archived_executions_owner_is_not_absent() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_archived(&pool, &t, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution_owner(exec, t.user).await.unwrap() {
        talos_execution_repository::ExecutionOwnerLookup::Archived { owner, archived_at } => {
            assert_eq!(owner, t.user);
            assert!(archived_at < chrono::Utc::now());
        }
        other => panic!(
            "an archived execution's owner must classify as Archived, not {other:?} — this gate \
             is what stood between an operator and 929 surviving worker-log lines"
        ),
    }
}

/// Control: a live execution's owner still classifies `Live`.
#[tokio::test]
async fn a_live_executions_owner_still_classifies_live() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_live(&pool, &t, "running").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution_owner(exec, t.user).await.unwrap() {
        talos_execution_repository::ExecutionOwnerLookup::Live(owner) => assert_eq!(owner, t.user),
        other => panic!("a live execution's owner must be Live, got {other:?}"),
    }
}

/// Tenancy. The archive leg of the owner lookup is user-scoped — strictly
/// TIGHTER than its live sibling, which is deliberately un-scoped so the
/// caller can log distinct "belongs to a different user" telemetry. So
/// another tenant's ARCHIVED execution must read `Absent`, never `Archived`:
/// otherwise the archived arm would tell user A that user B's execution
/// exists.
#[tokio::test]
async fn another_tenants_archived_execution_has_no_visible_owner() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let b_exec = seed_archived(&pool, &b, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution_owner(b_exec, a.user).await.unwrap() {
        talos_execution_repository::ExecutionOwnerLookup::Absent => {}
        other => {
            panic!("user A must not learn that user B's archived execution exists, got {other:?}")
        }
    }
}

/// The live leg stays UN-scoped on purpose: `submit_workflow_approval` logs a
/// distinct "belongs to a different user" event, which it can only do if the
/// read hands it the real owner rather than filtering the row away. Losing
/// that would be a silent regression in the opposite direction, so it is
/// pinned here rather than left to the comment.
#[tokio::test]
async fn a_live_foreign_execution_still_resolves_its_real_owner() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let b_exec = seed_live(&pool, &b, "waiting").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution_owner(b_exec, a.user).await.unwrap() {
        talos_execution_repository::ExecutionOwnerLookup::Live(owner) => assert_eq!(
            owner, b.user,
            "the live leg must return the TRUE owner so the caller can log the mismatch"
        ),
        other => panic!("expected Live(owner_b), got {other:?}"),
    }
}

/// The data the archived arm exists to show. `module_executions` /
/// `module_execution_logs` have no cascade to `workflow_executions`, so a
/// worker log line written under a now-archived parent is still readable by
/// the production query. If a future migration added a CASCADE, the archived
/// arm of `tail_worker_logs` would start rendering an empty list under a note
/// promising complete logs — this is the tripwire for that.
///
/// Main-vocabulary twin (FAILS BY ASSERTION on 4c74e7bf — not because the
/// logs are gone, but because the handler could never reach them: the
/// ownership gate answered `None` first):
///
/// ```ignore
/// assert!(repo.get_workflow_execution_owner(exec).await.unwrap().is_some());
/// ```
#[tokio::test]
async fn worker_logs_survive_the_archival_move() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_archived(&pool, &t, "completed").await;
    seed_worker_log(&pool, &t, exec, "gate=egress allowed").await;

    let repo = ExecutionRepository::new(pool.clone());
    let rows = repo
        .tail_workflow_logs(exec, None, Some("DEBUG"), None, 100)
        .await
        .expect("tail must not error for an archived parent");
    assert_eq!(
        rows.len(),
        1,
        "a worker log line written under a now-archived execution is still there — that is \
         what makes the pre-#749 \"not found\" answer a LOSS and not just a wrong diagnosis"
    );
    assert_eq!(rows[0].message, "gate=egress allowed");
}

// ── get_execution_base → lookup_execution_base ──────────────────────────────

/// **THE BUG, `get_execution_lineage` half.** Step 1 of the lineage handler
/// verified existence with `get_execution_base`, whose `None` it rendered as
/// "Execution not found or access denied".
///
/// Main-vocabulary twin (FAILS BY ASSERTION on 4c74e7bf):
///
/// ```ignore
/// let base = repo.get_execution_base(exec, t.user).await.unwrap();
/// assert!(base.is_some(), "an archived execution has base columns");
/// ```
#[tokio::test]
async fn an_archived_executions_base_columns_are_not_absent() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_archived(&pool, &t, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution_base(exec, t.user).await.unwrap() {
        talos_execution_repository::ExecutionBaseLookup::Archived { base, archived_at } => {
            assert_eq!(base.status, "completed");
            assert_eq!(base.workflow_id, t.workflow.to_string());
            assert!(archived_at < chrono::Utc::now());
        }
        other => panic!("an archived execution's base must be Archived, got {other:?}"),
    }
}

/// Control + tenancy for the base lookup, in one: a live row is `Live`, and
/// another tenant's archived row is `Absent`.
#[tokio::test]
async fn base_lookup_controls_live_and_cross_tenant() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let live = seed_live(&pool, &a, "running").await;
    let b_exec = seed_archived(&pool, &b, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo.lookup_execution_base(live, a.user).await.unwrap() {
        talos_execution_repository::ExecutionBaseLookup::Live(base) => {
            assert_eq!(base.status, "running")
        }
        other => panic!("expected Live, got {other:?}"),
    }
    match repo.lookup_execution_base(b_exec, a.user).await.unwrap() {
        talos_execution_repository::ExecutionBaseLookup::Absent => {}
        other => panic!("cross-tenant archived base must be Absent, got {other:?}"),
    }
}

// ── get_latest_execution_for_workflow → lookup_latest_… ─────────────────────

/// **THE SHARPEST OF THE FOUR.** `watch_execution(workflow_id)` asks for the
/// workflow's LATEST execution. Reading only the live table does not merely
/// fail to find it — it returns an OLDER execution AS the latest, with
/// nothing in the response marking it stale. Reachable because the retention
/// sweep skips pinned rows (`is_pinned = false` in `archive_move_sql`), so a
/// pinned older run outlives an unpinned newer one.
///
/// Main-vocabulary twin (FAILS BY ASSERTION on 4c74e7bf — it returns the
/// OLD live row, so this is a wrong ANSWER, not a missing one):
///
/// ```ignore
/// let latest = repo.get_latest_execution_for_workflow(t.workflow, t.user)
///     .await.unwrap().expect("some execution");
/// assert_eq!(latest.id, newer_archived, "the latest run is the archived one");
/// ```
#[tokio::test]
async fn the_latest_execution_may_be_the_archived_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;

    // An OLD live row (pinned, so the sweep would have left it) …
    let old_live = seed_live(&pool, &t, "completed").await;
    sqlx::query(
        "UPDATE workflow_executions SET started_at = NOW() - INTERVAL '90 days', \
         is_pinned = true WHERE id = $1",
    )
    .bind(old_live)
    .execute(&pool)
    .await
    .expect("age the live row");

    // … and a NEWER archived one (unpinned, so the sweep took it).
    let newer_archived = seed_archived(&pool, &t, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo
        .lookup_latest_execution_for_workflow(t.workflow, t.user)
        .await
        .unwrap()
    {
        ExecutionLookup::Archived { row, .. } => assert_eq!(
            row.id, newer_archived,
            "the newer ARCHIVED execution is the workflow's latest — returning the older live \
             one as \"latest\" is a wrong answer presented as a right one"
        ),
        other => panic!(
            "expected the archived row to win the ordering, got {other:?} (old_live={old_live})"
        ),
    }
}

/// The simpler half: a workflow whose runs have ALL aged out answered
/// "No executions found for this workflow" — false.
///
/// Main-vocabulary twin (FAILS BY ASSERTION on 4c74e7bf):
///
/// ```ignore
/// let latest = repo.get_latest_execution_for_workflow(t.workflow, t.user).await.unwrap();
/// assert!(latest.is_some(), "the workflow HAS executions — they are archived");
/// ```
#[tokio::test]
async fn a_workflow_whose_runs_all_aged_out_still_has_a_latest() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_archived(&pool, &t, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    match repo
        .lookup_latest_execution_for_workflow(t.workflow, t.user)
        .await
        .unwrap()
    {
        ExecutionLookup::Archived { row, .. } => assert_eq!(row.id, exec),
        other => panic!("expected Archived, got {other:?}"),
    }
}

/// Control: a live execution newer than an archived one still wins, and a
/// workflow with NO executions at all is still `Absent` — so the
/// operator-recognised "No executions found for this workflow" keeps meaning
/// what it always meant.
#[tokio::test]
async fn latest_execution_controls_live_wins_and_empty_is_absent() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let _old_archived = seed_archived(&pool, &t, "completed").await; // 40 days ago
    let new_live = seed_live(&pool, &t, "running").await; // NOW()

    let repo = ExecutionRepository::new(pool.clone());
    match repo
        .lookup_latest_execution_for_workflow(t.workflow, t.user)
        .await
        .unwrap()
    {
        ExecutionLookup::Live(row) => assert_eq!(row.id, new_live),
        other => panic!("a newer LIVE execution must still win, got {other:?}"),
    }

    let empty = seed_tenant(&pool).await;
    match repo
        .lookup_latest_execution_for_workflow(empty.workflow, empty.user)
        .await
        .unwrap()
    {
        ExecutionLookup::Absent => {}
        other => panic!("a workflow with no executions must be Absent, got {other:?}"),
    }
}

// ── get_workflow_id_any_user (platform-admin audit chain) ───────────────────

/// The cryptographic audit chain lives in the offline WORM ledger, keyed by
/// `(workflow_id, execution_id)` and entirely unaffected by the DB retention
/// sweep. Before the archive fallback, a platform admin auditing any
/// execution older than the retention window was told "Execution not found"
/// about a chain sitting intact in object storage. An audit surface that
/// stops at the archive boundary silently under-reports.
///
/// This method is DELIBERATELY cross-tenant (authorization is established
/// upstream by `is_platform_admin`), and the archive leg keeps that property
/// — asserted below with a SECOND tenant's row, so a future "fix" that
/// user-scoped it would fail here rather than silently restricting admins.
///
/// Main-vocabulary twin (FAILS BY ASSERTION on 4c74e7bf):
///
/// ```ignore
/// let wf = repo.get_workflow_id_any_user(exec).await.unwrap();
/// assert_eq!(wf, Some(t.workflow), "an archived execution still has a workflow");
/// ```
#[tokio::test]
async fn the_platform_admin_workflow_lookup_reaches_the_archive() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_archived(&pool, &t, "completed").await;

    let repo = ExecutionRepository::new(pool.clone());
    assert_eq!(
        repo.get_workflow_id_any_user(exec).await.unwrap(),
        Some(t.workflow),
        "the audit-chain lookup must resolve an archived execution's workflow — the ledger it \
         keys is untouched by archival"
    );

    // Controls: a live row still resolves, and an id that never existed is
    // still `None` so "Execution not found" keeps meaning absent.
    let live = seed_live(&pool, &t, "running").await;
    assert_eq!(
        repo.get_workflow_id_any_user(live).await.unwrap(),
        Some(t.workflow)
    );
    assert_eq!(
        repo.get_workflow_id_any_user(Uuid::new_v4()).await.unwrap(),
        None
    );
}

// ── get_execution_lineage_{root,tree} ───────────────────────────────────────

/// A lineage tree can legitimately span BOTH tables. `parent_execution_id`
/// and `root_execution_id` carry NO foreign key (unlike `replayed_from_id`,
/// which is `ON DELETE SET NULL` and is severed by the move), so an archived
/// member keeps its links and a live-only walk returns a SILENTLY TRUNCATED
/// tree — it does not error, it reports a smaller `total_executions_in_lineage`
/// as if that were the whole story.
///
/// Main-vocabulary twin (FAILS BY ASSERTION on 4c74e7bf — `len()` is 1 there,
/// and the signature difference is invisible to `.len()`):
///
/// ```ignore
/// let tree = repo.get_execution_lineage_tree(root, t.user).await.unwrap();
/// assert_eq!(tree.len(), 2, "the tree spans the live table and the archive");
/// ```
#[tokio::test]
async fn a_lineage_tree_spanning_both_tables_is_returned_whole() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;

    let root = seed_live(&pool, &t, "completed").await;
    let archived_child = seed_archived(&pool, &t, "completed").await;
    sqlx::query("UPDATE workflow_executions_archive SET root_execution_id = $1, parent_execution_id = $1 WHERE id = $2")
        .bind(root)
        .bind(archived_child)
        .execute(&pool)
        .await
        .expect("link the archived child to the live root");

    let repo = ExecutionRepository::new(pool.clone());
    let tree = repo.get_execution_lineage_tree(root, t.user).await.unwrap();
    assert_eq!(
        tree.len(),
        2,
        "the tree must include the archived child — a live-only walk truncates it silently and \
         then reports the truncated count as the total"
    );
    let child = tree
        .iter()
        .find(|n| n.id == archived_child)
        .expect("the archived child is in the tree");
    assert!(
        child.archived_at.is_some(),
        "…and it must be STAMPED as archived: a reader that does not say which table a node \
         came from is claiming a uniformity it did not check"
    );
    let live_root = tree.iter().find(|n| n.id == root).expect("the live root");
    assert!(
        live_root.archived_at.is_none(),
        "the live node must NOT be stamped"
    );
}

/// The lineage ROOT resolve also reads both tables — an archived anchor still
/// carries its `root_execution_id`, so it must not look standalone.
///
/// Main-vocabulary twin (FAILS BY ASSERTION on 4c74e7bf):
///
/// ```ignore
/// let root = repo.get_execution_lineage_root(archived, t.user).await.unwrap();
/// assert!(root.is_some(), "an archived execution still has lineage columns");
/// ```
#[tokio::test]
async fn an_archived_anchors_lineage_root_is_readable() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let root = seed_live(&pool, &t, "completed").await;
    let archived_child = seed_archived(&pool, &t, "completed").await;
    sqlx::query("UPDATE workflow_executions_archive SET root_execution_id = $1 WHERE id = $2")
        .bind(root)
        .bind(archived_child)
        .execute(&pool)
        .await
        .expect("link");

    let repo = ExecutionRepository::new(pool.clone());
    assert_eq!(
        repo.get_execution_lineage_root(archived_child, t.user)
            .await
            .unwrap(),
        Some((Some(root), None)),
        "an archived anchor must resolve to its real root, not read as standalone"
    );
}

/// Tenancy on the lineage tree: both halves of the UNION carry
/// `AND user_id = $2`, so another tenant's archived child must not appear in
/// user A's tree even when the ids are made to line up.
#[tokio::test]
async fn a_lineage_tree_does_not_reach_across_tenants() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;

    let root = seed_live(&pool, &a, "completed").await;
    let b_child = seed_archived(&pool, &b, "completed").await;
    sqlx::query("UPDATE workflow_executions_archive SET root_execution_id = $1 WHERE id = $2")
        .bind(root)
        .bind(b_child)
        .execute(&pool)
        .await
        .expect("link across tenants");

    let repo = ExecutionRepository::new(pool.clone());
    let tree = repo.get_execution_lineage_tree(root, a.user).await.unwrap();
    assert_eq!(
        tree.len(),
        1,
        "user A's lineage must contain only user A's rows, got {:?}",
        tree.iter().map(|n| n.id).collect::<Vec<_>>()
    );
}
