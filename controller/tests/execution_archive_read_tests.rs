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
