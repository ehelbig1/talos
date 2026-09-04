// Execution retention — ONE path, two tiers, and what each tier refuses.
//
// Before 2026-09-04 the platform had TWO loops removing rows from
// `workflow_executions` and the destructive one won every race:
//
//   * a 6-hourly plain `DELETE ... WHERE started_at < NOW() - retention AND
//     status != 'queued'`, spawned FIRST, and
//   * a daily archival CTE whose `INSERT INTO workflow_executions_archive
//     SELECT * FROM archived` had never once succeeded.
//
// `tokio::time::interval` fires its first tick immediately, so on every boot
// the DELETE ran first over a predicate that was a strict superset of the
// archival one. Measured on the dev fleet: the archive held 0 rows across the
// platform's entire history, and the oldest live execution was exactly 30 days
// old. The archival statement could not have worked anyway — the live table has
// 32 columns and the archive had 25, and `INSERT has more expressions than
// target columns` is a PARSE-time error (`DELETE ... WHERE false RETURNING *`
// raises it identically), so it had returned `Err` on every daily tick since
// 2026-03-26. `if let Ok(r) = result` discarded all of them.
//
// Retention is now one path: live --ARCHIVE_AFTER_DAYS--> archive
// --EXECUTION_RETENTION_DAYS--> gone.
//
// WHICH OF THESE TESTS FAIL ON PRISTINE MAIN, AND HOW — stated precisely,
// because "it fails on main" is worthless if it fails by compile error:
//
//   * `archive_schema_parity_in_the_database` and
//     `manual_archive_preserves_every_column` use ONLY vocabulary that exists
//     on main (`information_schema`, `AdvancedRepository::archive_executions`).
//     Both compile there and both FAIL BY ASSERTION. The second is the sharp
//     one: it drives the real production `archive_executions` — the `archive_
//     executions` MCP tool's implementation — and catches that it enumerated 24
//     of 32 columns and silently dropped the encrypted output payload and the
//     `org_id` tenancy pin. `list_archived_executions` selects six columns, so
//     that loss was invisible from every surface.
//   * `manual_archive_survives_a_replay_pair` also compiles on main and fails
//     by assertion there (FK violation), covering the two FK landmines.
//   * The `sweep_*` / `purge_*` / `pin_*` tests below name functions that do not
//     exist on main and therefore CANNOT be written in its vocabulary — the
//     retention pass was inline in `background.rs` and unreachable from a test.
//     They are stated here as new-behaviour coverage, not as main-failing
//     evidence; the three above carry that burden.
//
// Each test corresponds to one clause the sweeps must honour, and each clause
// exists because omitting it produces a specific failure:
//
//  * pinned rows — `pin_execution` promises an execution survives "for easy
//    reference later". The pre-change DELETE had no `is_pinned` reference at
//    all, so that promise was kept only by the loop that never ran. Latent when
//    measured (0 pinned executions existed), live the day anyone pins one.
//  * non-terminal rows — the old predicate excluded only `queued`, which takes
//    `running`, `resuming` and `pending` too. Latent and remote on this fleet
//    (0 in-flight rows; longest observed run 2h02m against a 30-day window),
//    wrong in principle.
//  * the purge clock — `archived_at`, not `completed_at`. With both windows at
//    30 days a `completed_at` purge would delete a row on the same sweep that
//    archived it, making the archive tier a no-op, which is where the platform
//    already was.
//  * non-positive windows — `make_interval(days => 0)` turns "older than N
//    days" into "older than now", i.e. everything. Same destructive-env family
//    as MCP-643/1062/1063.
//
// The archival and purge SWEEPS ARE FLEET-WIDE by design — they are the
// background tasks, and scoping them to one user would be testing something the
// controller does not run. So this binary requires `--test-threads=1`, which is
// exactly how `scripts/test-integration.sh` invokes every TC_TESTS entry; a
// bare `cargo test --test execution_retention_tests` will interleave the sweeps
// and flake. Assertions are id-scoped so a sweep picking up a sibling test's
// leftovers is harmless, but the ordering is not optional.
//
// Registered in `scripts/test-integration.sh`'s TC_TESTS list — that list is
// hand-maintained, and lint check 64 fails if a binary here is not named there.

mod test_helpers;

use talos_advanced_repository::AdvancedRepository;
use uuid::Uuid;

/// Every test in this binary shares ONE database — `test_helpers::get_test_db_pool`
/// is one container per binary — and three tests ALTER its schema (a column
/// rename on the archive; renaming `system_settings` away and back). Under
/// cargo's default parallel threads those races are real, not theoretical:
/// measured 6 failures on a plain `cargo test -p controller --test
/// execution_retention_tests`, 0 with `--test-threads=1`. CI happens to pass
/// that flag, so the suite's correctness lived in `scripts/test-integration.sh`
/// rather than here, and a developer's plain `cargo test` failed spuriously.
///
/// A second, DATA-level race hides behind the schema one: `sweep_archive_executions`,
/// `purge_archived_executions` and `run_retention_pass*` are deliberately GLOBAL
/// (a background task sweeps every tenant), so a test calling one of them moves
/// or purges rows that a concurrently-running test just inserted for itself —
/// measured as 3 further failures once the schema race was fixed, all in
/// user-scoped `archive_executions` tests whose rows had been swept out from
/// under them. So the rule is: any test that mutates the SCHEMA or runs a GLOBAL
/// sweep takes the lock EXCLUSIVELY; tests that only touch their own user's rows
/// SHARE it. No test upgrades a shared guard
/// to exclusive, so there is no deadlock path.
static SCHEMA_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

enum SchemaGuard {
    Shared(tokio::sync::RwLockReadGuard<'static, ()>),
    Exclusive(tokio::sync::RwLockWriteGuard<'static, ()>),
    /// A second fixture in the SAME test, covered by a sibling's guard. A test
    /// must never take `SCHEMA_LOCK` twice: tokio's RwLock is write-preferring,
    /// so read #1 held + a queued writer + read #2 requested is a deadlock
    /// (measured — the whole binary hung at 0% CPU with 0 tests completed
    /// the first time this file took two shared guards in one test).
    HeldBySibling,
}

struct Fixture {
    /// Held for the test's lifetime — see `SCHEMA_LOCK`.
    _schema: SchemaGuard,
    pool: sqlx::PgPool,
    repo: AdvancedRepository,
    user: Uuid,
    org: Uuid,
    actor: Uuid,
    workflow: Uuid,
    /// A real `encryption_keys` row. `workflow_executions.output_enc_key_id`
    /// carries an FK to it, so the encrypted-output columns cannot be
    /// exercised with a placeholder UUID — and exercising them is the whole
    /// point of `manual_archive_preserves_every_column`.
    dek: Uuid,
}

/// Shared-schema fixture: the default. Takes `SCHEMA_LOCK` for reading.
async fn fixture() -> Fixture {
    build_fixture(SchemaGuard::Shared(SCHEMA_LOCK.read().await)).await
}

/// Exclusive-schema fixture for the tests that ALTER the shared database.
/// Takes `SCHEMA_LOCK` for writing, so no shared-guard test runs concurrently.
async fn fixture_exclusive() -> Fixture {
    build_fixture(SchemaGuard::Exclusive(SCHEMA_LOCK.write().await)).await
}

/// Two fixtures (two users) under ONE shared guard — see `SchemaGuard::HeldBySibling`.
async fn fixture_pair() -> (Fixture, Fixture) {
    let a = build_fixture(SchemaGuard::Shared(SCHEMA_LOCK.read().await)).await;
    let b = build_fixture(SchemaGuard::HeldBySibling).await;
    (a, b)
}

async fn build_fixture(guard: SchemaGuard) -> Fixture {
    let pool = test_helpers::get_test_db_pool().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("ret-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();

    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("retorg-{tag}"))
    .bind(format!("retorg-{tag}"))
    .bind(user)
    .fetch_one(&pool)
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

    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, $4, 'inline://test', '{}'::jsonb)",
    )
    .bind(workflow)
    .bind(user)
    .bind(org)
    .bind(format!("retwf-{tag}"))
    .execute(&pool)
    .await
    .unwrap();

    // One active DEK per org (`idx_one_active_dek_per_org`); each fixture makes
    // its own org, so this never collides with a sibling test.
    let dek: Uuid = sqlx::query_scalar(
        "INSERT INTO encryption_keys (encrypted_key, org_id) VALUES ('\\x00'::bytea, $1) \
         RETURNING id",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();

    let repo = AdvancedRepository::new(pool.clone());
    Fixture {
        _schema: guard,
        pool,
        repo,
        user,
        org,
        actor,
        workflow,
        dek,
    }
}

/// Seed one live execution `age_days` old. `status` and `pinned` are the two
/// axes the sweeps are supposed to discriminate on.
async fn seed_execution(f: &Fixture, age_days: i32, status: &str, pinned: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, org_id, actor_id, status, started_at, completed_at, \
              is_pinned, output_data_enc, output_enc_key_id, output_data_format, epoch, \
              checkpoint_seq, pin_note) \
         VALUES ($1, $2, $3, $4, $5, $6, \
                 NOW() - make_interval(days => $7::int), \
                 NOW() - make_interval(days => $7::int), \
                 $8, '\\xdeadbeef'::bytea, $9, 4, 7, 11, 'keep me')",
    )
    .bind(id)
    .bind(f.workflow)
    .bind(f.user)
    .bind(f.org)
    .bind(f.actor)
    .bind(status)
    .bind(age_days)
    .bind(pinned)
    .bind(f.dek)
    .execute(&f.pool)
    .await
    .unwrap();
    id
}

async fn live_exists(f: &Fixture, id: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM workflow_executions WHERE id = $1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap()
        > 0
}

async fn archived_exists(f: &Fixture, id: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM workflow_executions_archive WHERE id = $1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap()
        > 0
}

// ── Schema parity — the gate the three hand-written sync migrations lacked ───

/// **This is the check that would have caught the whole outage on the day it
/// started.** Every column of `workflow_executions` must exist on
/// `workflow_executions_archive`, or an archival move cannot name it.
///
/// The archive was created `LIKE workflow_executions INCLUDING ALL` and then
/// hand-mirrored three times (`20260320000000`, `20260323000000`,
/// `20260323000100`). `20260320000000`'s own comment states the failure mode
/// verbatim — "fails with a column count mismatch even when zero rows are being
/// archived" — and it still went unmirrored for the next seven live columns and
/// five months, because a hand-fix is a snapshot, not a gate (checks 64/65).
///
/// Fails by assertion on pristine main: 32 live columns, 25 archive columns.
#[tokio::test]
async fn archive_schema_parity_in_the_database() {
    let f = fixture().await;
    let cols = |table: &'static str| {
        let pool = f.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 ORDER BY column_name",
            )
            .bind(table)
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };
    let live = cols("workflow_executions").await;
    let archive = cols("workflow_executions_archive").await;

    let missing: Vec<&String> = live.iter().filter(|c| !archive.contains(c)).collect();
    assert!(
        missing.is_empty(),
        "workflow_executions_archive is missing {} column(s) present on workflow_executions: \
         {missing:?}. An archival move cannot name them, so the sweep fails at PARSE time on \
         every tick and nothing is ever archived. Add them in a migration AND to \
         talos_advanced_repository::ARCHIVED_EXECUTION_COLUMNS.",
        missing.len()
    );

    // The archive is allowed exactly ONE column the live table does not have:
    // the purge clock. Anything else is drift in the other direction.
    let extra: Vec<&String> = archive
        .iter()
        .filter(|c| !live.contains(c) && c.as_str() != "archived_at")
        .collect();
    assert!(
        extra.is_empty(),
        "workflow_executions_archive has unexpected column(s) {extra:?}; only `archived_at` \
         (the purge clock) may exist on the archive and not on the live table"
    );
}

/// The Rust-side half of parity: the constant the SQL is built from must name
/// the live table exactly. Parity in the DB is not enough — a column present on
/// both tables but absent from the list is silently dropped on every move,
/// which is precisely the manual path's pre-change defect.
#[tokio::test]
async fn archive_column_constant_matches_the_live_table() {
    let f = fixture().await;
    let live = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'workflow_executions'",
    )
    .fetch_all(&f.pool)
    .await
    .unwrap();

    let listed: Vec<String> = talos_advanced_repository::ARCHIVED_EXECUTION_COLUMNS
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let unlisted: Vec<&String> = live.iter().filter(|c| !listed.contains(c)).collect();
    assert!(
        unlisted.is_empty(),
        "ARCHIVED_EXECUTION_COLUMNS does not name {unlisted:?}; those columns would be \
         SILENTLY DROPPED on archival (the pre-change manual path dropped eight this way, \
         including the encrypted output payload and org_id)"
    );
    let phantom: Vec<&String> = listed.iter().filter(|c| !live.contains(c)).collect();
    assert!(
        phantom.is_empty(),
        "ARCHIVED_EXECUTION_COLUMNS names {phantom:?}, which no longer exist on \
         workflow_executions; the archival SQL will fail to parse"
    );
}

// ── The manual path (`archive_executions` MCP tool) ──────────────────────────

/// An archived execution must BE the live execution. Compiles and fails by
/// assertion on pristine main, where `archive_executions` enumerated 24 of 32
/// columns and dropped `org_id`, `output_data_enc`, `output_enc_key_id`,
/// `output_data_format`, `checkpoint_seq`, `epoch`, `parent_execution_id` and
/// `root_execution_id` on the floor.
///
/// `org_id` and the `output_data_enc` triple are asserted by name rather than
/// counted: one is the tenancy pin, the other is the execution's actual output
/// under AEAD. Losing either without a word is worse than not archiving at all.
#[tokio::test]
async fn manual_archive_preserves_every_column() {
    let f = fixture().await;
    let id = seed_execution(&f, 40, "completed", false).await;

    let moved = f.repo.archive_executions(30, f.user).await.unwrap();
    assert_eq!(moved, 1, "the aged execution should have been archived");
    assert!(!live_exists(&f, id).await, "it must leave the live table");
    assert!(archived_exists(&f, id).await, "it must land in the archive");

    // Read the archived row as JSON rather than naming columns in a typed
    // SELECT. A typed SELECT would fail with `column "output_data_enc" does
    // not exist` on a tree where the archive lacks the column — a true
    // failure, but a Postgres error rather than a legible assertion. As JSON,
    // a dropped column is an ABSENT KEY and the assertion below says which one
    // and why it matters.
    let row: serde_json::Value = sqlx::query_scalar(
        "SELECT row_to_json(t) FROM workflow_executions_archive t WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();

    let field = |k: &str| -> &serde_json::Value {
        row.get(k).unwrap_or_else(|| {
            panic!(
                "the archived row has no `{k}` field at all — the archival move dropped the \
                 column on the floor. `list_archived_executions` selects six columns, so this \
                 loss is invisible from every surface; archived row was: {row}"
            )
        })
    };

    assert_eq!(
        field("org_id").as_str(),
        Some(f.org.to_string().as_str()),
        "org_id — the tenancy pin — must survive archival"
    );
    assert_eq!(
        field("output_data_enc").as_str(),
        Some("\\xdeadbeef"),
        "output_data_enc — the execution's actual output under AEAD — must survive archival"
    );
    assert_eq!(
        field("output_enc_key_id").as_str(),
        Some(f.dek.to_string().as_str()),
        "output_enc_key_id must survive — ciphertext without its DEK id cannot be decrypted"
    );
    assert_eq!(
        field("output_data_format").as_i64(),
        Some(4),
        "output_data_format must survive (a v4 row read as v0 cannot decrypt)"
    );
    assert_eq!(field("epoch").as_i64(), Some(7), "epoch must survive");
    assert_eq!(
        field("checkpoint_seq").as_i64(),
        Some(11),
        "checkpoint_seq must survive"
    );
}

/// Archiving must not be blocked by replay lineage.
///
/// Two FK landmines, both reproduced directly against the live schema before
/// this change, both of which make the whole batch abort:
///
///  * `workflow_executions_replayed_from_id_fkey` was `NO ACTION`, so deleting
///    a replay PARENT whose child was still live raised "violates foreign key
///    constraint". Because the sweeps delete in 5000-row batches and a
///    constraint violation aborts the entire statement, ONE such pair
///    straddling the boundary stopped retention permanently — for the archival
///    path and for the plain DELETE that existed then.
///  * `workflow_executions_archive_replayed_from_id_fkey` referenced the LIVE
///    table, so archiving a pair TOGETHER failed on insert: the parent was
///    deleted in the same statement that inserted the child.
///
/// Latent when measured (0 of 9,512 live executions had `replayed_from_id`
/// set), but `replay_execution` is a shipped tool. Compiles on main; fails
/// there by assertion, since `archive_executions` returns `Err`.
#[tokio::test]
async fn manual_archive_survives_a_replay_pair() {
    let f = fixture().await;
    let parent = seed_execution(&f, 40, "completed", false).await;
    let child = seed_execution(&f, 40, "completed", false).await;
    sqlx::query("UPDATE workflow_executions SET replayed_from_id = $1 WHERE id = $2")
        .bind(parent)
        .bind(child)
        .execute(&f.pool)
        .await
        .unwrap();

    let moved = f
        .repo
        .archive_executions(30, f.user)
        .await
        .expect("archiving a replay pair must not be blocked by referential integrity");
    assert_eq!(moved, 2, "both halves of the pair should be archived");
    assert!(archived_exists(&f, parent).await);
    assert!(archived_exists(&f, child).await);

    // Only the PARENT half of the lineage is deliberately lost: the live
    // self-FK is now ON DELETE SET NULL, so a child left behind in the live
    // table loses its pointer rather than blocking retention. Here both moved
    // together, so the pointer is carried across intact.
    let ptr: Option<Uuid> = sqlx::query_scalar(
        "SELECT replayed_from_id FROM workflow_executions_archive WHERE id = $1",
    )
    .bind(child)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        ptr,
        Some(parent),
        "the archive no longer holds an FK into the live table, so lineage moved together \
         keeps its pointer"
    );
}

/// A live replay child must not keep its archived parent alive.
///
/// The complementary half of the FK story: the parent ages out while the child
/// is still fresh. Pre-change this raised a constraint violation and aborted
/// the batch; now the parent archives and the child's pointer is NULLed. That
/// loss is the stated cost of `ON DELETE SET NULL` — under the plain DELETE it
/// replaced, the parent row was destroyed outright, so no link survived there
/// either.
#[tokio::test]
async fn a_live_replay_child_does_not_pin_its_parent() {
    let f = fixture().await;
    let parent = seed_execution(&f, 40, "completed", false).await;
    let child = seed_execution(&f, 1, "completed", false).await;
    sqlx::query("UPDATE workflow_executions SET replayed_from_id = $1 WHERE id = $2")
        .bind(parent)
        .bind(child)
        .execute(&f.pool)
        .await
        .unwrap();

    let moved = f
        .repo
        .archive_executions(30, f.user)
        .await
        .expect("a live replay CHILD must not block its aged parent from being archived");
    assert_eq!(moved, 1, "only the aged parent should move");
    assert!(archived_exists(&f, parent).await);
    assert!(
        live_exists(&f, child).await,
        "the fresh child must stay live"
    );

    let ptr: Option<Uuid> =
        sqlx::query_scalar("SELECT replayed_from_id FROM workflow_executions WHERE id = $1")
            .bind(child)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(ptr, None, "ON DELETE SET NULL, not a blocked batch");
}

// ── Tier 1: the fleet-wide archival sweep ───────────────────────────────────

/// The headline behaviour, and the one the platform never had: an aged
/// execution is MOVED, not deleted.
#[tokio::test]
async fn sweep_moves_an_aged_execution_into_the_archive() {
    let f = fixture_exclusive().await;
    let id = seed_execution(&f, 40, "completed", false).await;
    let fresh = seed_execution(&f, 1, "completed", false).await;

    f.repo.sweep_archive_executions(30).await.unwrap();

    assert!(
        !live_exists(&f, id).await,
        "the aged row must leave the live table"
    );
    assert!(
        archived_exists(&f, id).await,
        "and it must be IN THE ARCHIVE — on pristine main the competing 6-hourly DELETE \
         removed it instead and the archive stayed empty"
    );
    assert!(
        live_exists(&f, fresh).await,
        "a fresh row must be untouched"
    );
    assert!(!archived_exists(&f, fresh).await);

    let stamped: bool = sqlx::query_scalar(
        "SELECT archived_at > NOW() - INTERVAL '1 minute' FROM workflow_executions_archive \
         WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(stamped, "archived_at must record the moment of the move");
}

/// `pin_execution` promises the execution survives. The pre-change 6-hourly
/// DELETE had no `is_pinned` reference at all.
#[tokio::test]
async fn sweep_refuses_a_pinned_execution() {
    let f = fixture_exclusive().await;
    let pinned = seed_execution(&f, 400, "completed", true).await;
    f.repo.sweep_archive_executions(30).await.unwrap();
    assert!(
        live_exists(&f, pinned).await,
        "a pinned execution must stay exactly where the operator pinned it"
    );
    assert!(!archived_exists(&f, pinned).await);
}

/// `status != 'queued'` is not a terminal test. A `running` or `resuming`
/// execution is in flight; removing its row strands the worker's result.
#[tokio::test]
async fn sweep_refuses_a_non_terminal_execution() {
    let f = fixture_exclusive().await;
    // Every non-terminal status the live table's CHECK actually permits.
    // `pending` is deliberately absent: `workflow_executions_status_check`
    // rejects it (the archive table carries a STALE copy of that constraint,
    // frozen at `LIKE ... INCLUDING ALL` time, which permits `pending` and
    // rejects `queued`/`waiting`/`resuming` — a constraint-parity gap this
    // change does NOT close, and one the column-parity test cannot see).
    for status in ["running", "resuming", "waiting", "queued"] {
        let id = seed_execution(&f, 400, status, false).await;
        f.repo.sweep_archive_executions(30).await.unwrap();
        assert!(
            live_exists(&f, id).await,
            "a `{status}` execution must never be archived, however old it is"
        );
    }
}

// ── Tier 2: the archive purge ───────────────────────────────────────────────

/// The purge is clocked on `archived_at`, not `completed_at`.
///
/// This is the clause that makes the two-tier model non-degenerate. Both
/// windows default to 30 days, so a `completed_at` purge would select exactly
/// the rows the archival sweep had just moved — the archive tier would be a
/// no-op and the change would have reproduced the defect it fixes.
#[tokio::test]
async fn purge_is_clocked_on_time_kept_not_on_completion() {
    let f = fixture_exclusive().await;
    let id = seed_execution(&f, 400, "completed", false).await;
    f.repo.sweep_archive_executions(30).await.unwrap();
    assert!(archived_exists(&f, id).await);

    // Completed 400 days ago, archived seconds ago. A completed_at clock would
    // delete it; the archived_at clock must not.
    let purged = f.repo.purge_archived_executions(30).await.unwrap();
    assert_eq!(
        purged, 0,
        "a freshly archived row has been KEPT for zero days"
    );
    assert!(archived_exists(&f, id).await);

    // Backdate the keep clock past the window; now it is purgeable.
    sqlx::query(
        "UPDATE workflow_executions_archive SET archived_at = NOW() - INTERVAL '40 days' \
         WHERE id = $1",
    )
    .bind(id)
    .execute(&f.pool)
    .await
    .unwrap();
    let purged = f.repo.purge_archived_executions(30).await.unwrap();
    assert_eq!(purged, 1);
    assert!(!archived_exists(&f, id).await);
}

/// The purge is the only thing in the platform that permanently deletes an
/// execution record, so `is_pinned` has to hold here too — otherwise
/// `pin_execution`'s promise is kept for 30 days and then quietly broken.
#[tokio::test]
async fn purge_refuses_a_pinned_archived_execution() {
    let f = fixture_exclusive().await;
    let id = seed_execution(&f, 400, "completed", false).await;
    f.repo.sweep_archive_executions(30).await.unwrap();
    sqlx::query(
        "UPDATE workflow_executions_archive SET archived_at = NOW() - INTERVAL '400 days', \
         is_pinned = true WHERE id = $1",
    )
    .bind(id)
    .execute(&f.pool)
    .await
    .unwrap();

    let purged = f.repo.purge_archived_executions(30).await.unwrap();
    assert_eq!(
        purged, 0,
        "a pinned archived execution must never be purged"
    );
    assert!(archived_exists(&f, id).await);
}

/// Defence in depth: the archival sweep cannot put a non-terminal row in the
/// archive, but if one ever arrives by another route the purge must still
/// refuse it.
#[tokio::test]
async fn purge_refuses_a_non_terminal_archived_row() {
    let f = fixture_exclusive().await;
    let id = seed_execution(&f, 400, "completed", false).await;
    f.repo.sweep_archive_executions(30).await.unwrap();
    sqlx::query(
        "UPDATE workflow_executions_archive SET archived_at = NOW() - INTERVAL '400 days', \
         status = 'running' WHERE id = $1",
    )
    .bind(id)
    .execute(&f.pool)
    .await
    .unwrap();

    assert_eq!(f.repo.purge_archived_executions(30).await.unwrap(), 0);
    assert!(archived_exists(&f, id).await);
}

// ── End to end ──────────────────────────────────────────────────────────────

/// `pin_execution`'s promise, kept across the WHOLE path.
///
/// The point of asserting it end to end rather than per-sweep: on pristine main
/// the promise was honoured by exactly one of the two loops, and it was the
/// loop that had never run. A per-tier test would have passed there too.
#[tokio::test]
async fn a_pin_survives_the_entire_retention_path() {
    let f = fixture_exclusive().await;
    let pinned = seed_execution(&f, 4000, "completed", true).await;
    let doomed = seed_execution(&f, 4000, "completed", false).await;

    // Many passes, as the background tasks would run them.
    for _ in 0..3 {
        f.repo.sweep_archive_executions(30).await.unwrap();
        f.repo.purge_archived_executions(30).await.unwrap();
    }
    // Age the doomed row's keep clock and purge again.
    sqlx::query(
        "UPDATE workflow_executions_archive SET archived_at = NOW() - INTERVAL '400 days' \
         WHERE user_id = $1",
    )
    .bind(f.user)
    .execute(&f.pool)
    .await
    .unwrap();
    f.repo.purge_archived_executions(30).await.unwrap();

    assert!(
        live_exists(&f, pinned).await,
        "the pinned execution must still be live and readable after every sweep"
    );
    assert!(
        !live_exists(&f, doomed).await && !archived_exists(&f, doomed).await,
        "the unpinned one should have completed the path"
    );
}

/// `make_interval(days => 0)` turns "older than N days" into "older than now",
/// and a negative value into "older than the future". Either is a total purge
/// on the first sweep. Both tiers must refuse rather than proceed.
#[tokio::test]
async fn both_tiers_refuse_a_nonpositive_window() {
    let f = fixture_exclusive().await;
    let id = seed_execution(&f, 400, "completed", false).await;

    for days in [0, -1, -365] {
        assert_eq!(f.repo.sweep_archive_executions(days).await.unwrap(), 0);
        assert_eq!(f.repo.purge_archived_executions(days).await.unwrap(), 0);
        assert_eq!(f.repo.archive_executions(days, f.user).await.unwrap(), 0);
    }
    assert!(
        live_exists(&f, id).await,
        "nothing may move on a non-positive window"
    );
}

// ── The retention PASS — the wiring layer, now under test ───────────────────
//
// Everything above tests the two tier functions in isolation. These test the
// PASS: the thing `background.rs` actually calls. They exist because two
// mutations of the pre-extraction wiring survived every test above, and both
// were silent:
//
//   * re-instating the swallowed archival `Result` — the exact defect this
//     change exists to remove, and the reason a broken sweep went unnoticed for
//     five months;
//   * swapping the two windows, which at their shared default of 30 days turns
//     the archive tier back into a no-op — the original bug, reproduced.
//
// Neither could be caught while the logic lived inside a `tokio::spawn` block a
// test cannot call. Both are now inside
// `talos_advanced_repository::{resolve_retention_windows, run_retention_pass}`.

use talos_advanced_repository::{
    resolve_retention_windows, run_retention_pass, RetentionWindowDecision, RetentionWindows,
};

/// Move a row into the archive and backdate its keep clock, as if it had been
/// archived `archived_days_ago` ago.
async fn seed_archived(f: &Fixture, completed_days_ago: i32, archived_days_ago: i32) -> Uuid {
    let id = seed_execution(f, completed_days_ago, "completed", false).await;
    f.repo.archive_executions(1, f.user).await.unwrap();
    sqlx::query(
        "UPDATE workflow_executions_archive \
         SET archived_at = NOW() - make_interval(days => $2::int) WHERE id = $1",
    )
    .bind(id)
    .bind(archived_days_ago)
    .execute(&f.pool)
    .await
    .unwrap();
    id
}

/// **The M6 guard.** An archive statement that cannot run must come back as an
/// ERROR, not as "nothing to archive".
///
/// The break is not synthetic — it reproduces the historical failure exactly.
/// Renaming a column the archival INSERT names puts the statement back in the
/// state it was in from 2026-03-26 to 2026-09-04: unparseable, failing on every
/// tick, indistinguishable (to the pre-extraction caller) from a quiet pass.
///
/// The schema is restored BEFORE the assertions so a failing assertion cannot
/// leave the shared container's archive table broken for later tests. This
/// binary runs `--test-threads=1`, which is what makes the window safe at all.
#[tokio::test]
async fn an_unrunnable_archive_statement_is_reported_not_hidden() {
    let f = fixture_exclusive().await;
    seed_execution(&f, 400, "completed", false).await;

    sqlx::query("ALTER TABLE workflow_executions_archive RENAME COLUMN org_id TO org_id__broken")
        .execute(&f.pool)
        .await
        .unwrap();

    let outcome = run_retention_pass(
        &f.repo,
        RetentionWindows {
            archive_after_days: 30,
            purge_after_days: 30,
        },
    )
    .await;

    sqlx::query("ALTER TABLE workflow_executions_archive RENAME COLUMN org_id__broken TO org_id")
        .execute(&f.pool)
        .await
        .unwrap();

    assert!(
        outcome.archive_error.is_some(),
        "a retention pass whose archive statement cannot run MUST surface the error. \
         Reporting archived=0 with no error is the five-month outage verbatim: nothing \
         else in the system can tell 'nothing was old enough' from 'the move is broken'. \
         outcome = {outcome:?}"
    );
    assert!(
        outcome.failed(),
        "failed() must agree with the recorded error: {outcome:?}"
    );
    assert_eq!(
        outcome.archived, 0,
        "a failed archive moved nothing: {outcome:?}"
    );
}

/// A pass with nothing to do must NOT look like a failed pass — the converse of
/// the guard above, and the reason the outcome carries a count and an error
/// separately rather than collapsing to a bool.
#[tokio::test]
async fn a_quiet_pass_is_not_a_failed_pass() {
    let f = fixture_exclusive().await;
    seed_execution(&f, 1, "completed", false).await;

    let outcome = run_retention_pass(
        &f.repo,
        RetentionWindows {
            archive_after_days: 30,
            purge_after_days: 30,
        },
    )
    .await;

    assert!(!outcome.failed(), "nothing was old enough: {outcome:?}");
    assert_eq!(outcome.archive_error, None);
    assert_eq!(outcome.purge_error, None);
}

/// **The M7 guard.** Each window must govern its OWN tier.
///
/// The windows are deliberately far apart (10 / 40) and the fixtures sit
/// BETWEEN them, because at the shared production default of 30 a swap is
/// invisible by construction — which is exactly why the pre-extraction mutation
/// was silent and why this test cannot be written with equal windows.
///
/// With the windows applied correctly:
///   * a live row completed 20 days ago is past `archive_after_days` (10) and
///     is MOVED;
///   * an archived row kept 20 days is within `purge_after_days` (40) and SURVIVES;
///   * an archived row kept 50 days is past it and is PURGED.
///
/// Swap the two and the first two assertions invert: 20 < 40 so nothing is
/// archived, and 20 > 10 so the kept row is destroyed.
#[tokio::test]
async fn each_window_governs_its_own_tier() {
    let f = fixture_exclusive().await;
    let to_archive = seed_execution(&f, 20, "completed", false).await;
    let keep_archived = seed_archived(&f, 100, 20).await;
    let purge_archived = seed_archived(&f, 100, 50).await;

    let outcome = run_retention_pass(
        &f.repo,
        RetentionWindows {
            archive_after_days: 10,
            purge_after_days: 40,
        },
    )
    .await;
    assert!(!outcome.failed(), "{outcome:?}");

    assert!(
        !live_exists(&f, to_archive).await && archived_exists(&f, to_archive).await,
        "a row 20 days past completion is past archive_after_days=10 and must be MOVED. \
         If the windows are swapped it is compared against 40 instead and stays live — \
         which at the production default of 30/30 would be invisible."
    );
    assert!(
        archived_exists(&f, keep_archived).await,
        "an archived row kept 20 days is within purge_after_days=40 and must SURVIVE. \
         If the windows are swapped it is compared against 10 and is destroyed."
    );
    assert!(
        !archived_exists(&f, purge_archived).await,
        "an archived row kept 50 days is past purge_after_days=40 and must be PURGED \
         (otherwise this test would pass with a purge that does nothing at all)"
    );
}

/// A just-archived row is never purged by the pass that archived it, whatever
/// the windows say.
///
/// This is the property that makes the two-tier model non-degenerate, and it
/// holds because the purge is clocked on `archived_at`. Asserted with windows
/// that would destroy the row on a `completed_at` clock: 400 days completed,
/// purge window 30.
#[tokio::test]
async fn the_pass_never_purges_what_it_just_archived() {
    let f = fixture_exclusive().await;
    let id = seed_execution(&f, 400, "completed", false).await;

    let outcome = run_retention_pass(
        &f.repo,
        RetentionWindows {
            archive_after_days: 30,
            purge_after_days: 30,
        },
    )
    .await;

    assert!(!outcome.failed(), "{outcome:?}");
    assert!(
        archived_exists(&f, id).await,
        "a row completed 400 days ago but archived seconds ago has been KEPT for zero \
         days; on a completed_at purge clock the same pass would delete it and the \
         archive tier would be a no-op"
    );
}

/// A pin survives the pass — end to end, through both tiers, repeatedly.
#[tokio::test]
async fn the_pass_never_touches_a_pinned_execution() {
    let f = fixture_exclusive().await;
    let pinned = seed_execution(&f, 4000, "completed", true).await;
    for _ in 0..3 {
        let outcome = run_retention_pass(
            &f.repo,
            RetentionWindows {
                archive_after_days: 1,
                purge_after_days: 1,
            },
        )
        .await;
        assert!(!outcome.failed(), "{outcome:?}");
    }
    assert!(
        live_exists(&f, pinned).await,
        "pin_execution promises the execution survives; the pass must honour it"
    );
}

// ── Window resolution ───────────────────────────────────────────────────────

/// The two windows are not interchangeable, and this is the ONLY place that
/// decides which is which.
///
/// `resolve_retention_windows` exists so the caller never holds two bare
/// integers it could pass in the wrong order — the shape that let the swap live
/// silently at the call site. Pinning the mapping here is what makes the
/// remaining single site checkable.
#[tokio::test]
async fn windows_are_not_interchangeable() {
    // EXCLUSIVE: this test mutates process-global env vars, which is a global
    // mutation like a schema ALTER — no shared-guard test may run beside it.
    let f = fixture_exclusive().await;
    sqlx::query("DELETE FROM system_settings WHERE key = 'archive_after_days'")
        .execute(&f.pool)
        .await
        .unwrap();
    // The first version of this test asserted `w.archive_after_days ==
    // talos_config::archive_after_days()` and the purge window against
    // `execution_retention_days()` — i.e. against the very two functions the
    // resolver reads. At the production default BOTH are 30, so swapping the
    // two sources inside the resolver yields the identical `{30, 30}` and the
    // assertions still hold: the mutation SURVIVED, measured. A guard that only
    // fails when the two windows differ has to make them differ.
    let prev_a = std::env::var("ARCHIVE_AFTER_DAYS").ok();
    let prev_r = std::env::var("EXECUTION_RETENTION_DAYS").ok();
    std::env::set_var("ARCHIVE_AFTER_DAYS", "10");
    std::env::set_var("EXECUTION_RETENTION_DAYS", "40");
    let resolved = resolve_retention_windows(&f.pool).await;
    match prev_a {
        Some(v) => std::env::set_var("ARCHIVE_AFTER_DAYS", v),
        None => std::env::remove_var("ARCHIVE_AFTER_DAYS"),
    }
    match prev_r {
        Some(v) => std::env::set_var("EXECUTION_RETENTION_DAYS", v),
        None => std::env::remove_var("EXECUTION_RETENTION_DAYS"),
    }
    let RetentionWindowDecision::Run(w) = resolved else {
        panic!("a readable (absent) setting must resolve, not skip");
    };
    assert_eq!(
        (w.archive_after_days, w.purge_after_days),
        (10, 40),
        "ARCHIVE_AFTER_DAYS must govern the LIVE-table window and \
         EXECUTION_RETENTION_DAYS the ARCHIVE window — got archive={} purge={}, \
         which is what a swapped resolver produces",
        w.archive_after_days,
        w.purge_after_days
    );
}

/// The DB override governs the ARCHIVE tier only, and a non-positive value is
/// ignored rather than obeyed.
///
/// `make_interval(days => 0)` turns "older than N days" into "older than now",
/// i.e. every completed execution on the next tick (MCP-758 / MCP-643).
#[tokio::test]
async fn the_db_override_governs_the_archive_tier_and_refuses_nonpositive() {
    let f = fixture().await;
    let set = |v: i64| {
        let pool = f.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO system_settings (key, value, updated_at) \
                 VALUES ('archive_after_days', $1::jsonb, NOW()) \
                 ON CONFLICT (key) DO UPDATE SET value = $1::jsonb",
            )
            .bind(serde_json::json!(v))
            .execute(&pool)
            .await
            .unwrap();
        }
    };

    set(7).await;
    let RetentionWindowDecision::Run(w) = resolve_retention_windows(&f.pool).await else {
        panic!("readable setting must resolve");
    };
    assert_eq!(
        w.archive_after_days, 7,
        "the override governs the ARCHIVE tier"
    );
    assert_eq!(
        w.purge_after_days,
        talos_config::execution_retention_days(),
        "and must NOT leak into the purge tier"
    );

    for bad in [0, -5] {
        set(bad).await;
        let RetentionWindowDecision::Run(w) = resolve_retention_windows(&f.pool).await else {
            panic!("readable setting must resolve");
        };
        assert_eq!(
            w.archive_after_days,
            talos_config::archive_after_days(),
            "archive_after_days={bad} must be ignored, not obeyed — it would archive \
             every completed execution on the next tick"
        );
    }

    sqlx::query("DELETE FROM system_settings WHERE key = 'archive_after_days'")
        .execute(&f.pool)
        .await
        .unwrap();
}

/// An UNREADABLE setting is not an unset one (#661), preserved through the
/// extraction.
///
/// A DB fault must skip the pass, not substitute the env default onto a
/// statement that DELETEs from `workflow_executions` — an operator running
/// 365-day retention would otherwise have ~11 months swept out on the next tick.
#[tokio::test]
async fn an_unreadable_setting_skips_the_pass_rather_than_guessing() {
    let f = fixture_exclusive().await;
    sqlx::query("ALTER TABLE system_settings RENAME TO system_settings__hidden")
        .execute(&f.pool)
        .await
        .unwrap();

    let decision = resolve_retention_windows(&f.pool).await;

    sqlx::query("ALTER TABLE system_settings__hidden RENAME TO system_settings")
        .execute(&f.pool)
        .await
        .unwrap();

    assert!(
        matches!(decision, RetentionWindowDecision::SkipUnreadable(_)),
        "a setting that cannot be READ must skip the pass, never fall back to the env \
         default: got {decision:?}"
    );
}

/// The manual archive is scoped to ONE user's executions.
///
/// **This test exists because the extraction silently removed the coverage that
/// used to catch a tenancy regression, and the loss was only visible under
/// mutation.** Before the pass-level tests were added, dropping the
/// `AND user_id = $2` predicate from `archive_executions` was caught by
/// `manual_archive_preserves_every_column` asserting `moved == 1` — an unscoped
/// query swept up other tests' leftover aged rows and moved more than one. That
/// catch was an ACCIDENT of cross-test residue, not a guard: once
/// `run_retention_pass` began sweeping the whole table fleet-wide earlier in the
/// run, no residue was left, `moved == 1` held, and the mutation survived.
///
/// A coverage guarantee that depends on another test leaving litter behind is
/// not a guarantee. This one seeds two users deliberately.
///
/// It is also load-bearing rather than belt-and-braces: `TALOS_RLS_SET_ROLE`
/// defaults OFF, so on the superuser pool these tests (and the dev deployment)
/// run against, RLS does NOT backstop this query — the app-layer predicate is
/// the only thing scoping it. Same shape as `ml_registry_tenancy_tests`.
#[tokio::test]
async fn the_manual_archive_is_scoped_to_one_user() {
    let (a, b) = fixture_pair().await;
    let a_row = seed_execution(&a, 40, "completed", false).await;
    let b_row = seed_execution(&b, 40, "completed", false).await;

    let moved = a.repo.archive_executions(30, a.user).await.unwrap();

    assert_eq!(
        moved, 1,
        "archive_executions must move only the CALLING user's executions; \
         moving {moved} means another tenant's rows were swept up"
    );
    assert!(
        archived_exists(&a, a_row).await,
        "the caller's own aged execution should be archived"
    );
    assert!(
        live_exists(&b, b_row).await && !archived_exists(&b, b_row).await,
        "another user's aged execution must be untouched by A's call — RLS is not \
         enforced on this pool, so the AND user_id = $2 predicate is the only scoping"
    );
}

/// **The M10 guard.** An unreadable window skips the WHOLE pass — nothing is
/// swept, on a guess or otherwise.
///
/// This drives `run_retention_pass_from_config`, the single entry point
/// `background.rs` calls. It exists because the previous shape — the spawn loop
/// matching on `RetentionWindowDecision` itself — left one decision in the
/// wiring, and a mutation that ignored `SkipUnreadable` and swept on a
/// fabricated 30/30 guess survived the entire suite. No test could reach it,
/// because no test can call a `tokio::spawn` body.
///
/// The stakes are #661's: an operator running 365-day retention would have had
/// ~11 months of executions swept out of the live table on the next tick,
/// because a DB fault was indistinguishable from an unset setting.
///
/// The aged row is the load-bearing assertion. A test that only checked the
/// reported skip would still pass if the pass swept first and reported second.
#[tokio::test]
async fn an_unreadable_window_skips_the_whole_pass() {
    let f = fixture_exclusive().await;
    let aged = seed_execution(&f, 4000, "completed", false).await;

    sqlx::query("ALTER TABLE system_settings RENAME TO system_settings__hidden")
        .execute(&f.pool)
        .await
        .unwrap();

    let outcome = talos_advanced_repository::run_retention_pass_from_config(&f.repo, &f.pool).await;

    sqlx::query("ALTER TABLE system_settings__hidden RENAME TO system_settings")
        .execute(&f.pool)
        .await
        .unwrap();

    assert!(
        outcome.skipped_window.is_some(),
        "an unreadable archive window must be REPORTED as a skip: {outcome:?}"
    );
    assert_eq!(
        outcome.archived, 0,
        "a skipped pass moves nothing: {outcome:?}"
    );
    assert_eq!(
        outcome.purged, 0,
        "a skipped pass purges nothing: {outcome:?}"
    );
    assert!(
        live_exists(&f, aged).await,
        "a 4000-day-old execution must STILL BE LIVE after a skipped pass — if the pass \
         fell back to the env default it would have been swept, which is exactly the \
         error-as-absence defect #661 closed"
    );
}

/// The config-driven entry point actually runs when the window IS readable —
/// the control for the test above, so a `run_retention_pass_from_config` that
/// skipped unconditionally could not pass both.
#[tokio::test]
async fn the_config_driven_pass_runs_when_the_window_is_readable() {
    let f = fixture_exclusive().await;
    let aged = seed_execution(&f, 4000, "completed", false).await;

    let outcome = talos_advanced_repository::run_retention_pass_from_config(&f.repo, &f.pool).await;

    assert_eq!(outcome.skipped_window, None, "{outcome:?}");
    assert!(
        outcome.windows.is_some(),
        "a pass that ran reports its windows: {outcome:?}"
    );
    assert!(!outcome.failed(), "{outcome:?}");
    assert!(
        archived_exists(&f, aged).await,
        "with a readable window the pass must actually archive: {outcome:?}"
    );
}
