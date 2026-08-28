// Module-execution ROW retention sweep — the safety properties, end to end.
//
// The sweep DELETEs whole `module_executions` rows and CASCADEs their
// `module_execution_logs` children. That is strictly more destructive than its
// payload-nulling sibling (`module_payload_retention_tests.rs`): the payload
// sweep leaves a `payload_pruned_at` tombstone, so a later reader can tell that
// data was removed and when. This one leaves nothing — a deleted execution and
// one that never ran are the same absence.
//
// So, as with that sibling, what needs proving is not "does it free space" but
// "what does it refuse to touch". Each test below corresponds to one clause of
// the conjunctive predicate, and each clause exists because omitting it produces
// a specific, named failure:
//
//  * `never_deletes_a_non_terminal_row` — a `running` row is an in-flight
//    dispatch; deleting it strands the worker's result with nothing to write to.
//  * `never_deletes_a_row_whose_parent_is_alive` — the clause that makes this a
//    GAP CLOSURE rather than a new retention policy. It deletes only what the
//    parent `workflow_executions` sweep would already have taken, had the
//    foreign key that was never added been there.
//  * `preserves_the_whole_corpus_of_a_rarely_run_module` — the one that kills
//    the age-only design, and it bites harder here than in the payload sweep.
//    `replay_module_regression` and `generate_typed_scaffold` read
//    `status='completed'` rows ranked by `completed_at DESC NULLS LAST,
//    started_at DESC`, with the MCP handler clamping `limit` to [1, 20]. No
//    reader in the workspace is bounded by AGE. For a module that ran three
//    times a year ago and went quiet, its entire corpus is also its oldest data
//    — an age policy deletes exactly those rows and the replay tool reports an
//    empty corpus with no error.
//  * `deletes_a_parentless_standalone_run` — the `workflow_execution_id IS NULL`
//    arm. `NOT EXISTS (… we.id = NULL)` is TRUE, so a standalone `run_sandbox` /
//    `test_module` row is eligible on age alone, which is correct (it has no
//    workflow parent by design) but non-obvious enough to pin. 0 of 36,942 rows
//    on the dev fleet are in this state, so production data does not cover it.
//  * `cascades_the_execution_logs` — the deletion's blast radius is larger than
//    its row count, and that is load-bearing for the batch-size reasoning.
//  * `refuses_a_nonpositive_retention_window` — `=0` makes the age belt
//    `created_at < NOW()`, i.e. every terminal parentless row on the first
//    sweep. Same destructive-env family as MCP-1063.
//
// Registered in `scripts/test-integration.sh`'s TC_TESTS list — that list is
// hand-maintained, so a binary added here and not added there runs NOWHERE.

mod test_helpers;

use std::sync::Arc;
use talos_module_executions::ModuleExecutionService;
use uuid::Uuid;

/// Seeds users/organizations/modules/actors/workflows and returns the ids the
/// execution rows need. Each call is independent so tests can share one
/// container DB.
struct Fixture {
    pool: sqlx::PgPool,
    svc: ModuleExecutionService,
    user: Uuid,
    module: Uuid,
    actor: Uuid,
    workflow: Uuid,
}

async fn fixture() -> Fixture {
    let pool = test_helpers::get_test_db_pool().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("rr-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();

    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("rrorg-{tag}"))
    .bind(format!("rrorg-{tag}"))
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

    let module = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, wasm_bytes, capability_world, kind) \
         VALUES ($1, $2, $3, '\\x00'::bytea, 'minimal-node', 'sandbox')",
    )
    .bind(module)
    .bind(user)
    .bind(format!("rrmod-{tag}"))
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
    .bind(format!("rrwf-{tag}"))
    .execute(&pool)
    .await
    .unwrap();

    let svc = ModuleExecutionService::new(
        pool.clone(),
        Arc::new(talos_dlp_provider::DlpService::from_env()),
    );
    Fixture {
        pool,
        svc,
        user,
        module,
        actor,
        workflow,
    }
}

/// Inserts a LIVE parent `workflow_executions` row and returns its id.
async fn seed_parent(f: &Fixture) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status) \
         VALUES ($1, $2, $3, $4, 'completed')",
    )
    .bind(id)
    .bind(f.workflow)
    .bind(f.user)
    .bind(f.actor)
    .execute(&f.pool)
    .await
    .unwrap();
    id
}

/// Inserts a `module_executions` row `age_days` old.
///
/// `parent`:
///   * `Some(id)` — points at that `workflow_executions` row. Pass an id that
///     was never inserted to model the ORPHAN case (there is no FK, which is
///     the entire defect this sweep closes, so a dangling uuid is accepted by
///     the database exactly as it is on the live fleet).
///   * `None` — a standalone run with no workflow parent.
async fn seed_row(f: &Fixture, status: &str, age_days: i32, parent: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    let completed_at = if status == "pending" || status == "running" {
        None
    } else {
        Some(age_days)
    };
    sqlx::query(
        "INSERT INTO module_executions \
           (id, module_id, user_id, actor_id, status, trigger_type, \
            workflow_execution_id, payload_format, \
            started_at, completed_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, 'manual', $6, 4, \
                 NOW() - make_interval(days => $7::int), \
                 CASE WHEN $8::int IS NULL THEN NULL \
                      ELSE NOW() - make_interval(days => $8::int) END, \
                 NOW() - make_interval(days => $7::int))",
    )
    .bind(id)
    .bind(f.module)
    .bind(f.user)
    .bind(f.actor)
    .bind(status)
    .bind(parent)
    .bind(age_days)
    .bind(completed_at)
    .execute(&f.pool)
    .await
    .unwrap();
    id
}

/// Does the row still exist?
async fn exists(pool: &sqlx::PgPool, id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM module_executions WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Sweep away anything an EARLIER test left deletable, so this test's counts
/// are attributable to its own fixture.
///
/// Tests share one container database and the sweep is global by design — it
/// has no tenant filter, because retention is a system concern. Two tests here
/// deliberately end with a deletable row still present
/// (`never_deletes_a_non_terminal_row` does not, but
/// `refuses_a_nonpositive_retention_window` does, and must: the whole point is
/// that the row survived). Without this drain, the next test to run counts
/// those rows as its own — which is exactly how `the_sweep_is_idempotent` first
/// reported 4 deletions for 3 seeded rows.
///
/// Deliberately uses the PRODUCTION sweep rather than a hand-written DELETE, so
/// the fixture cannot drift from the behaviour under test. Rows belonging to
/// other fixtures that the sweep declines to take (live parent, inside a
/// corpus, non-terminal) are left alone here for the same reasons they are left
/// alone in the test body, so they cannot perturb a count either.
async fn drain(f: &Fixture) {
    loop {
        let s = f
            .svc
            .delete_expired_executions(30, 20, 20_000)
            .await
            .unwrap();
        if s.deleted_rows == 0 {
            break;
        }
    }
}

/// A dangling parent id — a uuid that is not in `workflow_executions`. This is
/// exactly the live-fleet shape: 9,104 of 36,942 rows point at a parent the
/// 30-day retention DELETE removed, and no FK stopped them.
fn dead_parent() -> Option<Uuid> {
    Some(Uuid::new_v4())
}

#[tokio::test]
async fn never_deletes_a_non_terminal_row() {
    let f = fixture().await;
    drain(&f).await;
    // Old enough, parentless — but still running. A worker is going to write a
    // terminal status to this row.
    let running = seed_row(&f, "running", 400, dead_parent()).await;
    let pending = seed_row(&f, "pending", 400, dead_parent()).await;

    let stats = f.svc.delete_expired_executions(30, 50, 5000).await.unwrap();

    assert!(
        exists(&f.pool, running).await,
        "a running row is live state"
    );
    assert!(
        exists(&f.pool, pending).await,
        "a pending row is live state"
    );
    assert_eq!(stats.deleted_rows, 0);
}

#[tokio::test]
async fn never_deletes_a_row_whose_parent_is_alive() {
    let f = fixture().await;
    drain(&f).await;
    let parent = seed_parent(&f).await;
    // Terminal, 400 days old, outside any plausible corpus — and yet it must
    // survive, because its parent workflow execution still exists. This is the
    // clause that keeps the sweep a gap closure rather than an independent
    // retention policy.
    let child = seed_row(&f, "timeout", 400, Some(parent)).await;

    let stats = f.svc.delete_expired_executions(30, 50, 5000).await.unwrap();

    assert!(
        exists(&f.pool, child).await,
        "a row with a surviving parent must never be deleted, at any age"
    );
    assert_eq!(stats.deleted_rows, 0);
    // Two distinct assertions, and both matter. `Some` proves the probe was
    // MEASURED — `None` is what a failed count reports, and a swallowed count
    // reporting 0 was the defect this Option exists to prevent. `>= 1` proves
    // it counted the row we just skipped. `drain()` cannot remove such a row
    // (a live parent is precisely what the sweep refuses), so a reused
    // container DB could carry more than one; the lower bound is the honest
    // claim.
    let skipped = stats
        .retained_parent_alive
        .expect("the parent-alive probe must be measured, not swallowed");
    assert!(
        skipped >= 1,
        "the skip must be REPORTED, not silent — otherwise `deleted_rows = 0` \
         cannot be told apart from a broken predicate"
    );
}

#[tokio::test]
async fn deletes_an_old_orphan() {
    let f = fixture().await;
    drain(&f).await;
    // The live-fleet majority case: terminal, older than the age floor, parent
    // already removed by the workflow_executions retention DELETE.
    let orphan = seed_row(&f, "timeout", 400, dead_parent()).await;
    // A young orphan: its parent is gone too, but it has not aged out. Orphaned
    // is not sufficient — the age belt still applies. 86 rows on the dev fleet
    // are in exactly this state.
    let young = seed_row(&f, "timeout", 5, dead_parent()).await;

    let stats = f.svc.delete_expired_executions(30, 50, 5000).await.unwrap();

    assert!(!exists(&f.pool, orphan).await, "old + orphaned + terminal");
    assert!(
        exists(&f.pool, young).await,
        "orphaned alone is not enough; the age belt still applies"
    );
    assert_eq!(stats.deleted_rows, 1);
    assert_eq!(stats.batches, 1);
}

#[tokio::test]
async fn preserves_the_whole_corpus_of_a_rarely_run_module() {
    let f = fixture().await;
    drain(&f).await;
    // Three completed runs, all a year old, parents long gone, and nothing
    // since. These are simultaneously the module's OLDEST rows and its ENTIRE
    // replay corpus. An age-only policy deletes all three.
    let mut ids = Vec::new();
    for age in [360, 365, 370] {
        ids.push(seed_row(&f, "completed", age, dead_parent()).await);
    }

    let stats = f.svc.delete_expired_executions(30, 50, 5000).await.unwrap();

    for id in &ids {
        assert!(
            exists(&f.pool, *id).await,
            "the replay corpus of a rarely-run module must survive retention — \
             an age-only policy fails exactly here"
        );
    }
    assert_eq!(
        stats.deleted_rows, 0,
        "nothing in this fixture is outside the corpus"
    );
}

#[tokio::test]
async fn deletes_beyond_the_corpus_only() {
    let f = fixture().await;
    drain(&f).await;
    // corpus_keep = 20 (the REPLAY_REACH floor). Seed 25 completed rows, ages
    // 100..124 so rank tracks age: ranks 1..20 protected, 21..25 deletable.
    let mut ids = Vec::new();
    for i in 0..25 {
        ids.push(seed_row(&f, "completed", 100 + i, dead_parent()).await);
    }

    let stats = f.svc.delete_expired_executions(30, 20, 5000).await.unwrap();
    assert_eq!(stats.deleted_rows, 5, "ranks 21..25 only");

    for (rank, id) in ids.iter().enumerate() {
        let alive = exists(&f.pool, *id).await;
        if rank < 20 {
            assert!(alive, "rank {} is inside the replay reach", rank + 1);
        } else {
            assert!(!alive, "rank {} is outside the corpus", rank + 1);
        }
    }
}

#[tokio::test]
async fn corpus_keep_is_clamped_up_to_the_replay_reach() {
    let f = fixture().await;
    drain(&f).await;
    // A caller asking to keep 1 is asking for the silent-empty-corpus failure
    // by configuration. The floor is REPLAY_REACH (20), the furthest rank
    // `replay_module_regression` can reach.
    for i in 0..25 {
        seed_row(&f, "completed", 100 + i, dead_parent()).await;
    }

    let stats = f.svc.delete_expired_executions(30, 1, 5000).await.unwrap();

    assert_eq!(
        stats.deleted_rows, 5,
        "corpus_keep=1 must be clamped up to 20, leaving only ranks 21..25"
    );
}

#[tokio::test]
async fn deletes_a_parentless_standalone_run() {
    let f = fixture().await;
    drain(&f).await;
    // `workflow_execution_id IS NULL` — a standalone run_sandbox / test_module
    // row. `NOT EXISTS (… we.id = NULL)` is TRUE, so it is eligible on age
    // alone. Correct (it has no workflow parent by design) but non-obvious, and
    // unexercised by live data: 0 of 36,942 dev-fleet rows are in this state.
    let old = seed_row(&f, "failed", 400, None).await;
    let young = seed_row(&f, "failed", 5, None).await;

    let stats = f.svc.delete_expired_executions(30, 50, 5000).await.unwrap();

    assert!(
        !exists(&f.pool, old).await,
        "a NULL parent satisfies NOT EXISTS"
    );
    assert!(exists(&f.pool, young).await, "the age belt still applies");
    assert_eq!(stats.deleted_rows, 1);
}

#[tokio::test]
async fn cascades_the_execution_logs() {
    let f = fixture().await;
    drain(&f).await;
    let doomed = seed_row(&f, "timeout", 400, dead_parent()).await;
    let kept = seed_row(&f, "timeout", 5, dead_parent()).await;
    for id in [doomed, kept] {
        for level in ["INFO", "WARN", "ERROR"] {
            sqlx::query(
                "INSERT INTO module_execution_logs (execution_id, level, message) \
                 VALUES ($1, $2, 'm')",
            )
            .bind(id)
            .bind(level)
            .execute(&f.pool)
            .await
            .unwrap();
        }
    }

    f.svc.delete_expired_executions(30, 50, 5000).await.unwrap();

    let orphaned_logs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM module_execution_logs WHERE execution_id = $1")
            .bind(doomed)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        orphaned_logs, 0,
        "the FK cascade is what makes a row deletion reclaim its 2.33 average \
         log rows — the blast radius the batch size is sized against"
    );

    let surviving_logs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM module_execution_logs WHERE execution_id = $1")
            .bind(kept)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(surviving_logs, 3, "a surviving row keeps its logs");
}

#[tokio::test]
async fn the_sweep_is_idempotent() {
    let f = fixture().await;
    drain(&f).await;
    for _ in 0..3 {
        seed_row(&f, "timeout", 400, dead_parent()).await;
    }

    let first = f.svc.delete_expired_executions(30, 50, 5000).await.unwrap();
    assert_eq!(first.deleted_rows, 3);

    let second = f.svc.delete_expired_executions(30, 50, 5000).await.unwrap();
    assert_eq!(
        second.deleted_rows, 0,
        "a deleted row is self-excluding from the predicate"
    );
}

#[tokio::test]
async fn refuses_a_nonpositive_retention_window() {
    let f = fixture().await;
    drain(&f).await;
    let row = seed_row(&f, "timeout", 400, dead_parent()).await;

    for days in [0, -1, -3650] {
        let stats = f
            .svc
            .delete_expired_executions(days, 50, 5000)
            .await
            .unwrap();
        assert_eq!(
            stats.deleted_rows, 0,
            "retention_days={days} must fail closed: the age belt would become \
             `created_at < NOW()` and take every terminal parentless row"
        );
    }
    assert!(exists(&f.pool, row).await);

    // A non-positive batch size is the same class of refusal.
    let stats = f.svc.delete_expired_executions(30, 50, 0).await.unwrap();
    assert_eq!(stats.deleted_rows, 0);
    assert!(exists(&f.pool, row).await);
}

#[tokio::test]
async fn batches_are_bounded_and_resume_across_sweeps() {
    let f = fixture().await;
    drain(&f).await;
    for _ in 0..7 {
        seed_row(&f, "timeout", 400, dead_parent()).await;
    }

    // batch_size = 3 → batches of 3, 3, 1 within one sweep (the short batch
    // ends it). Proves the loop terminates on a short batch rather than on the
    // cap, and that the per-batch bound is honoured.
    let stats = f.svc.delete_expired_executions(30, 50, 3).await.unwrap();
    assert_eq!(stats.deleted_rows, 7);
    assert_eq!(stats.batches, 3, "3 + 3 + 1");
}
