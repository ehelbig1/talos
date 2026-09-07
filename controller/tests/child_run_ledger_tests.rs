//! A child run must leave a trace — RFC 0012 P1.
//!
//! `execute_subworkflow_graph` runs a child workflow IN-PROCESS and records no
//! `workflow_executions` row. Measured platform-wide 2026-09-05 and again
//! 2026-09-06 against the reference fleet: ZERO rows carry a
//! `parent_execution_id`, live table AND archive, against an estimated ~225
//! child runs per day. Every reader that asks *"did this workflow run, how
//! often, how recently?"* reads that table, so a child is invisible to all of
//! them — #758/#760/#762/#763 taught the destructive and scoring readers to
//! say "no evidence" instead of "never ran", and none of them can ANSWER the
//! question.
//!
//! WHAT THESE TESTS ARE, STATED PRECISELY — because "it fails on main" is
//! worthless if it fails by compile error, and claiming a main-failing twin
//! that does not exist is worse than claiming nothing.
//!
//! **Every test here pins NEW behaviour.** `sub_workflow_runs` does not exist
//! on pristine `origin/main`; neither does `ChildRunRecorder`,
//! `ChildRunLedger`, nor the `origin` parameter on
//! `execute_subworkflow_graph`. There is no main-vocabulary twin to run,
//! because on main there is nothing that could be asked the question. The
//! burden is therefore carried by MUTATION rather than by a pre-fix tree, and
//! each test below names the mutation that turns it red. Those mutations were
//! performed and the results are recorded in `AGENT_NOTES.md`.
//!
//! Every test drives REAL production code against a real Postgres: the real
//! `ParallelWorkflowEngine` chokepoint with the real
//! `PostgresChildRunRecorder` wired to it, the real repository methods, the
//! real RLS policy, and the real retention purge. A pure-Rust test cannot
//! cover any of this — the questions are which row landed, which policy
//! applied to it, and which rows a DELETE selected.

mod common;

use std::sync::Arc;

use talos_child_run_ledger::ChildRunLedger;
use talos_engine::child_run_recorder::PostgresChildRunRecorder;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{ChildRunOrigin, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher,
    memory::{InMemoryModuleFetcher, InMemoryWorkflowGraphStore},
    minimal_engine,
};
use uuid::Uuid;

// ── seeds ───────────────────────────────────────────────────────────────────

struct Seeded {
    user: Uuid,
    org: Uuid,
    /// Stands in for the PARENT workflow definition. Named `parent`/`child`
    /// rather than after any real workflow — nothing in a tracked file should
    /// carry a fleet workflow name.
    parent_workflow: Uuid,
    child_workflow: Uuid,
    actor: Uuid,
}

async fn seed_tenant(pool: &sqlx::PgPool) -> Seeded {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@ledger.test"))
    .execute(pool)
    .await
    .expect("seed user");

    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("ledorg-{tag}"))
    .bind(format!("ledorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");

    let wf = |name: &str| {
        let id = Uuid::new_v4();
        let name = format!("{name}-{tag}");
        (id, name)
    };
    let (parent_workflow, parent_name) = wf("parent");
    let (child_workflow, child_name) = wf("child");
    for (id, name) in [(parent_workflow, parent_name), (child_workflow, child_name)] {
        sqlx::query(
            "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
             VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb)",
        )
        .bind(id)
        .bind(user)
        .bind(org)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed workflow");
    }

    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("ledactor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");

    Seeded {
        user,
        org,
        parent_workflow,
        child_workflow,
        actor,
    }
}

/// A live `workflow_executions` row, optionally pinned.
async fn seed_live_execution(pool: &sqlx::PgPool, t: &Seeded, pinned: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, org_id, actor_id, status, started_at, is_pinned) \
         VALUES ($1, $2, $3, $4, $5, 'completed', NOW(), $6)",
    )
    .bind(id)
    .bind(t.parent_workflow)
    .bind(t.user)
    .bind(t.org)
    .bind(t.actor)
    .bind(pinned)
    .execute(pool)
    .await
    .expect("seed live execution");
    id
}

/// An ARCHIVED `workflow_executions_archive` row, optionally pinned. The
/// pinned-parent exemption has to hold on this tier too: `pin_execution`'s
/// promise must survive the parent's own archival move.
async fn seed_archived_execution(pool: &sqlx::PgPool, t: &Seeded, pinned: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions_archive \
             (id, workflow_id, user_id, org_id, status, started_at, completed_at, \
              is_pinned, archived_at) \
         VALUES ($1, $2, $3, $4, 'completed', NOW() - INTERVAL '200 days', \
                 NOW() - INTERVAL '200 days', $5, NOW() - INTERVAL '100 days')",
    )
    .bind(id)
    .bind(t.parent_workflow)
    .bind(t.user)
    .bind(t.org)
    .bind(pinned)
    .execute(pool)
    .await
    .expect("seed archived execution");
    id
}

/// One ledger row placed directly, `age_days` old. Used by the retention and
/// tenancy tests, which are about which rows a statement SELECTS — not about
/// how they got there.
async fn seed_ledger_row(
    pool: &sqlx::PgPool,
    t: &Seeded,
    parent_exec: Uuid,
    age_days: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sub_workflow_runs \
             (id, parent_execution_id, parent_workflow_id, parent_node_id, dispatch_kind, \
              child_workflow_id, user_id, actor_id, depth, started_at, completed_at, \
              status, duration_ms) \
         VALUES ($1, $2, $3, 'n1', 'sub_workflow', $4, $5, $6, 1, \
                 NOW() - make_interval(days => $7::int), \
                 NOW() - make_interval(days => $7::int), 'completed', 12)",
    )
    .bind(id)
    .bind(parent_exec)
    .bind(t.parent_workflow)
    .bind(t.child_workflow)
    .bind(t.user)
    .bind(t.actor)
    .bind(age_days)
    .execute(pool)
    .await
    .expect("seed ledger row");
    id
}

fn stub_artifact(id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "stub".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

/// A parent engine wired to the REAL recorder, ready to dispatch a child whose
/// single module returns `response`.
fn parent_engine(
    pool: &sqlx::PgPool,
    t: &Seeded,
    response: serde_json::Value,
) -> (
    talos_workflow_engine::ParallelWorkflowEngine,
    Arc<ScriptedDispatcher>,
) {
    parent_engine_bound_to(pool, t, response, Some(t.actor))
}

/// The same rig with the parent's bound actor as a PARAMETER, so a test can
/// build the engine the way an unresolved binding used to leave it: with no
/// actor at all. `None` is not a permissive actor — it is the Tier-1 fail-safe
/// with no tenancy principal — and the ledger row is where that becomes
/// visible after the fact.
fn parent_engine_bound_to(
    pool: &sqlx::PgPool,
    t: &Seeded,
    response: serde_json::Value,
    actor: Option<Uuid>,
) -> (
    talos_workflow_engine::ParallelWorkflowEngine,
    Arc<ScriptedDispatcher>,
) {
    let module_id = Uuid::new_v4();
    let child_graph = WorkflowGraphBuilder::new()
        .add_module("work", module_id, None)
        .build()
        .expect("child graph builds");

    let mut parent = minimal_engine();
    parent.set_user_id(t.user);
    parent.set_workflow_id(t.parent_workflow);
    if let Some(a) = actor {
        parent.set_actor_id(a);
    }
    // The REAL controller sanitizer, not the passthrough stub: `error_class`
    // redaction is one of the things under test, and a passthrough would make
    // the assertion vacuous.
    parent.set_output_sanitizer(Arc::new(talos_engine::sanitizer::DlpSanitizer::new()));
    parent.set_child_run_recorder(Arc::new(PostgresChildRunRecorder::new(pool.clone())));
    parent.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module_id, stub_artifact(module_id)),
    ));
    parent.set_graph_store(Arc::new(
        InMemoryWorkflowGraphStore::new().with_graph(t.child_workflow, child_graph),
    ));
    let dispatcher = Arc::new(ScriptedDispatcher::new().with_response(module_id, response));
    (parent, dispatcher)
}

// ── the chokepoint ──────────────────────────────────────────────────────────

/// **THE THING THIS PR EXISTS FOR.** A child that ran leaves a row.
///
/// Drives the REAL `execute_subworkflow_graph` with the REAL
/// `PostgresChildRunRecorder`, so it covers the whole chain: the origin
/// threaded from the dispatch site, the label lookup, the depth arithmetic,
/// the record type, the INSERT and every CHECK on the table.
///
/// MUTATION that turns it red: delete the `self.record_child_run(...)` await
/// at the tail of `execute_subworkflow_graph`.
#[tokio::test]
async fn a_completed_child_run_is_recorded_by_the_real_chokepoint() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let parent_exec = seed_live_execution(&pool, &t, false).await;

    let (parent, dispatcher) = parent_engine(&pool, &t, serde_json::json!({ "ok": true }));
    let node_id = Uuid::new_v4();

    parent
        .execute_subworkflow_graph(
            t.child_workflow,
            serde_json::json!({}),
            dispatcher,
            None,
            ChildRunOrigin::Node {
                execution_id: parent_exec,
                node_id,
                kind: talos_workflow_engine_core::ChildDispatchKind::SubWorkflow,
            },
        )
        .await
        .expect("the child runs");

    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            Uuid,
            String,
            String,
            Option<Uuid>,
            i16,
            String,
            Option<String>,
            i64,
        ),
    >(
        "SELECT parent_execution_id, child_workflow_id, parent_node_id, dispatch_kind, \
                actor_id, depth, status, error_class, duration_ms \
         FROM sub_workflow_runs WHERE user_id = $1",
    )
    .bind(t.user)
    .fetch_one(&pool)
    .await
    .expect("exactly one ledger row for a child that ran");

    assert_eq!(row.0, parent_exec, "parent execution id");
    assert_eq!(row.1, t.child_workflow, "child workflow id");
    // No label was registered for this synthetic node, so the writer falls back
    // to the node UUID — the documented fallback, asserted rather than assumed.
    assert_eq!(row.2, node_id.to_string(), "parent node id");
    assert_eq!(row.3, "sub_workflow", "dispatch kind");
    assert_eq!(
        row.4,
        Some(t.actor),
        "the EFFECTIVE actor the child ran as — inherited from the parent here, \
         because no sub-actor binding resolver is wired"
    );
    assert_eq!(
        row.5, 1,
        "a direct child is depth 1, not 0 and not the parent's"
    );
    assert_eq!(row.6, "completed");
    assert_eq!(row.7, None, "a completed run carries no error_class");
    assert!(row.8 >= 0, "duration must be a real measurement");
}

/// A child whose engine returned `Ok` can still have FAILED: its collapsed
/// output may carry an error envelope, which is what the reactor itself reads
/// to decide the parent node's fate. The ledger must agree with the run.
///
/// Also covers the two things that keep the ledger from becoming a payload
/// store: the message is DLP-REDACTED (the real sanitizer, not a passthrough)
/// and CAPPED at 512 characters.
///
/// MUTATIONS that turn it red: (a) classify with `.get("__error").as_bool()`
/// instead of `output_reports_error`; (b) drop the
/// `.take(MAX_ERROR_CLASS_CHARS)` in `ChildRunRecord::sanitized` — which
/// fails on the DB CHECK, the second belt doing its job.
///
/// **STATED LIMIT, measured rather than assumed.** Dropping the chokepoint's
/// own `self.redact_str(...)` does NOT turn this red, and the reason is worth
/// knowing: `run_scheduler_loop` DLP-redacts the whole results map on its way
/// out (`engine.rs`, "Two-pass scrub"), so a collapsed child output has
/// already been through one pass by the time the ledger sees it. The
/// chokepoint's redaction is therefore a SECOND pass on the `Ok` branch — and
/// the ONLY pass on the `Err` branch, where the text is an engine error
/// string that never went near the sanitizer. This test covers the stored
/// value being redacted; it does not, and cannot with an `Ok` envelope, prove
/// which layer did it.
#[tokio::test]
async fn a_failed_child_is_recorded_as_failed_with_a_redacted_capped_error() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let parent_exec = seed_live_execution(&pool, &t, false).await;

    // An error message that is (a) over the cap and (b) carries something DLP
    // must remove. A placeholder address, never a real one.
    let long_secret_bearing = format!("upstream rejected child@example.test {}", "x".repeat(900));
    let (parent, dispatcher) = parent_engine(
        &pool,
        &t,
        // A STRING `__error`, not `true`. This is the shape check 77 exists
        // for: a module, a custom `NodeDispatcher` or an LLM can author this
        // key, and `.as_bool().unwrap_or(false)` reads every non-boolean value
        // as a CLEAN RUN. With `true` here the test could not tell the shared
        // classifier from a second `as_bool()` opinion.
        serde_json::json!({ "__error": "upstream 502", "error_message": long_secret_bearing }),
    );

    parent
        .execute_subworkflow_graph(
            t.child_workflow,
            serde_json::json!({}),
            dispatcher,
            None,
            ChildRunOrigin::Node {
                execution_id: parent_exec,
                node_id: Uuid::new_v4(),
                kind: talos_workflow_engine_core::ChildDispatchKind::Judge,
            },
        )
        .await
        .expect("the child ran — it returned an error ENVELOPE, not an engine error");

    let (status, error_class, kind): (String, Option<String>, String) = sqlx::query_as(
        "SELECT status, error_class, dispatch_kind FROM sub_workflow_runs WHERE user_id = $1",
    )
    .bind(t.user)
    .fetch_one(&pool)
    .await
    .expect("one ledger row");

    assert_eq!(
        status, "failed",
        "a child whose collapsed output reports an error is a FAILED child — that is \
         check 77's classifier, the same one the reactor uses for the parent node"
    );
    assert_eq!(kind, "judge");
    let error_class = error_class.expect("a failed run carries an error_class");
    assert!(
        !error_class.contains("child@example.test"),
        "error_class must pass through the same redaction execution error messages \
         get; found the raw value: {error_class}"
    );
    assert!(
        error_class.contains("[REDACTED:EMAIL]"),
        "the redaction must have actually fired: {error_class}"
    );
    assert!(
        error_class.chars().count() <= 512,
        "error_class must be capped at 512 characters before the bind; got {}",
        error_class.chars().count()
    );
}

/// An operator PROBE (`test_subworkflow_contract`) is not a parent's run.
/// Recording one would put a run in the ledger that no workflow performed, and
/// every consumer counting "how often is this child dispatched" would count
/// the author testing it.
///
/// MUTATION that turns it red: make `record_child_run` fall through on
/// `ChildRunOrigin::Untracked` instead of returning.
#[tokio::test]
async fn an_untracked_probe_records_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;

    let (parent, dispatcher) = parent_engine(&pool, &t, serde_json::json!({ "ok": true }));
    parent
        .execute_subworkflow_graph(
            t.child_workflow,
            serde_json::json!({}),
            dispatcher,
            None,
            ChildRunOrigin::Untracked,
        )
        .await
        .expect("the child runs");

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0, "a probe must leave no ledger row");
}

// ── UNKNOWN is not zero ─────────────────────────────────────────────────────

/// `since()` is the discriminator between "nothing ran" and "nobody was
/// recording". On an EMPTY ledger it must be `None` — not `now()`, which would
/// silently claim that every earlier period was measured and empty.
#[tokio::test]
async fn since_is_unknown_on_an_empty_ledger_and_the_floor_once_a_row_exists() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let ledger = ChildRunLedger::new(pool.clone());

    ChildRunLedger::reset_since_cache();
    assert_eq!(
        ledger.since().await.expect("since reads"),
        None,
        "an empty ledger must answer UNKNOWN, never a timestamp"
    );

    let parent_exec = seed_live_execution(&pool, &t, false).await;
    seed_ledger_row(&pool, &t, parent_exec, 3).await;
    seed_ledger_row(&pool, &t, parent_exec, 9).await;

    ChildRunLedger::reset_since_cache();
    let since = ledger
        .since()
        .await
        .expect("since reads")
        .expect("a non-empty ledger has a floor");
    let age_days = (chrono::Utc::now() - since).num_days();
    assert_eq!(
        age_days, 9,
        "the floor is the EARLIEST row the ledger still holds, not the latest"
    );
}

/// A batched count, and — the part that matters — a child with no rows is
/// ABSENT from the map rather than present as 0. The caller decides what an
/// absence means, and before `ledger_since` it means UNKNOWN.
#[tokio::test]
async fn counts_are_batched_and_a_child_with_no_rows_is_absent_not_zero() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let parent_exec = seed_live_execution(&pool, &t, false).await;
    seed_ledger_row(&pool, &t, parent_exec, 1).await;
    seed_ledger_row(&pool, &t, parent_exec, 2).await;

    let never_ran = Uuid::new_v4();
    let counts = ChildRunLedger::new(pool.clone())
        .count_for_children_since(
            &[t.child_workflow, never_ran],
            t.user,
            chrono::Utc::now() - chrono::Duration::days(30),
        )
        .await
        .expect("counts read");

    assert_eq!(counts.get(&t.child_workflow).copied(), Some(2));
    assert_eq!(
        counts.get(&never_ran).copied(),
        None,
        "a child with no rows must be ABSENT from the map — a 0 here would be a \
         measurement the query never made"
    );

    // The window is a real predicate, not decoration.
    let recent = ChildRunLedger::new(pool.clone())
        .count_for_children_since(
            &[t.child_workflow],
            t.user,
            chrono::Utc::now() - chrono::Duration::hours(36),
        )
        .await
        .expect("counts read");
    assert_eq!(recent.get(&t.child_workflow).copied(), Some(1));
}

// ── tenancy ─────────────────────────────────────────────────────────────────

/// The app-layer predicate: another tenant's parent execution id returns
/// nothing even though the row exists.
#[tokio::test]
async fn a_read_is_scoped_to_the_calling_user() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let b_exec = seed_live_execution(&pool, &b, false).await;
    seed_ledger_row(&pool, &b, b_exec, 1).await;

    let rows = ChildRunLedger::new(pool.clone())
        .list_for_parent(b_exec, a.user, 50)
        .await
        .expect("read");
    assert!(
        rows.is_empty(),
        "user A must not read user B's child runs by naming their execution id"
    );

    let own = ChildRunLedger::new(pool.clone())
        .list_for_parent(b_exec, b.user, 50)
        .await
        .expect("read");
    assert_eq!(own.len(), 1, "the owner must still see their own row");
    assert_eq!(own[0].dispatch_kind, "sub_workflow");
    assert_eq!(own[0].depth, 1);
}

/// The RLS backstop, with the app-layer predicate deliberately REMOVED — the
/// mutation "someone dropped `AND user_id = $2`" expressed as a test. This
/// table carried a policy from its first migration precisely because the
/// archive did not (#748) and held tenant data unprotected for as long as it
/// held rows.
#[tokio::test]
async fn the_ledger_is_rls_isolated_from_another_tenant() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let b_exec = seed_live_execution(&pool, &b, false).await;
    let b_row = seed_ledger_row(&pool, &b, b_exec, 1).await;

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
    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs WHERE id = $1")
        .bind(b_row)
        .fetch_one(&mut *tx)
        .await
        .expect("count under talos_app");
    tx.commit().await.expect("commit");

    assert_eq!(
        visible, 0,
        "user B's child run must be invisible to user A even with the app-layer \
         user_id predicate removed"
    );
}

/// The control the test above needs: a policy of `USING (false)` would pass it
/// while hiding every child run from its owner.
#[tokio::test]
async fn the_owner_still_sees_their_own_child_run_under_rls() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let a_exec = seed_live_execution(&pool, &a, false).await;
    let a_row = seed_ledger_row(&pool, &a, a_exec, 1).await;

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
    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs WHERE id = $1")
        .bind(a_row)
        .fetch_one(&mut *tx)
        .await
        .expect("count under talos_app");
    tx.commit().await.expect("commit");

    assert_eq!(visible, 1, "the owner must read their own child run");
}

/// The structural twin: RLS ENABLED and FORCED, and the policy present by
/// name. Cheap, and it fails loudly if a future migration disables either.
#[tokio::test]
async fn the_ledger_schema_is_rls_enabled_and_forced() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (enabled, forced): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
         WHERE oid = 'sub_workflow_runs'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("read pg_class");
    assert!(enabled, "RLS must be ENABLED on sub_workflow_runs");
    assert!(forced, "RLS must be FORCED so it binds the table owner too");

    let policies: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_policies WHERE tablename = 'sub_workflow_runs' \
           AND policyname = 'sub_workflow_runs_tenant_isolation'",
    )
    .fetch_one(&pool)
    .await
    .expect("read pg_policies");
    assert_eq!(
        policies, 1,
        "the tenant-isolation policy must exist by name"
    );
}

// ── retention ───────────────────────────────────────────────────────────────

/// The purge deletes what is old, keeps what is recent, and EXEMPTS a row
/// whose parent execution is pinned — in EITHER tier, because `pin_execution`'s
/// promise must survive the parent's own archival move.
///
/// MUTATIONS that turn it red: delete either `NOT EXISTS` clause in
/// `purge_older_than`.
#[tokio::test]
async fn the_purge_spares_a_recent_row_and_a_pinned_parents_row_in_both_tiers() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;

    let unpinned_live = seed_live_execution(&pool, &t, false).await;
    let pinned_live = seed_live_execution(&pool, &t, true).await;
    let pinned_archived = seed_archived_execution(&pool, &t, true).await;

    let old_deletable = seed_ledger_row(&pool, &t, unpinned_live, 200).await;
    let old_pinned_live = seed_ledger_row(&pool, &t, pinned_live, 200).await;
    let old_pinned_archived = seed_ledger_row(&pool, &t, pinned_archived, 200).await;
    let recent = seed_ledger_row(&pool, &t, unpinned_live, 3).await;

    let purged = ChildRunLedger::new(pool.clone())
        .purge_older_than(90)
        .await
        .expect("purge runs");
    assert_eq!(purged, 1, "exactly the one deletable row");

    for (id, why) in [
        (
            old_pinned_live,
            "a row whose parent is pinned in the LIVE tier",
        ),
        (
            old_pinned_archived,
            "a row whose parent is pinned in the ARCHIVE tier",
        ),
        (recent, "a row inside the retention window"),
    ] {
        let survives: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(survives, 1, "{why} must survive the purge");
    }
    let gone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs WHERE id = $1")
        .bind(old_deletable)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(gone, 0, "the old, unpinned row must be deleted");
}

/// `make_interval(days => 0)` selects everything. A non-positive window must
/// refuse loudly and delete NOTHING — the same guard
/// `purge_archived_executions` carries, for the same reason.
#[tokio::test]
async fn the_purge_refuses_a_non_positive_window() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_live_execution(&pool, &t, false).await;
    seed_ledger_row(&pool, &t, exec, 400).await;

    for days in [0, -1, -365] {
        assert_eq!(
            ChildRunLedger::new(pool.clone())
                .purge_older_than(days)
                .await
                .expect("purge returns Ok(0) rather than erroring"),
            0,
            "days = {days} must delete nothing"
        );
    }
    let survives: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(survives, 1, "a refused purge must leave the ledger intact");
}

/// The retention pass's THIRD tier is wired, and it is clocked on the TOTAL
/// lifetime. A pass at `archive_after=30 / purge_after=60` must not delete a
/// 45-day-old ledger row — the parent is still readable in the archive at that
/// age, and deleting the record of a child run while its parent survives is
/// exactly the asymmetry the missing FK exists to avoid.
///
/// MUTATION that turns it red: pass `windows.archive_after_days` instead of
/// the sum in `run_retention_pass`.
#[tokio::test]
async fn the_retention_pass_trims_the_ledger_at_the_total_lifetime() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_live_execution(&pool, &t, false).await;
    let inside_total = seed_ledger_row(&pool, &t, exec, 45).await;
    let past_total = seed_ledger_row(&pool, &t, exec, 120).await;

    let repo = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let outcome = talos_advanced_repository::run_retention_pass(
        &repo,
        talos_advanced_repository::RetentionWindows {
            archive_after_days: 30,
            purge_after_days: 60,
        },
    )
    .await;

    assert_eq!(
        outcome.ledger_purge_error, None,
        "the ledger tier must not fail: {outcome:?}"
    );
    assert_eq!(outcome.ledger_purged, 1, "exactly the row past 90 days");

    let alive: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs WHERE id = $1")
        .bind(inside_total)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        alive, 1,
        "a 45-day-old child run must survive a 30/60 pass — its parent is still \
         readable in the archive"
    );
    let dead: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs WHERE id = $1")
        .bind(past_total)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(dead, 0);
}

// ── the two non-negotiables ────────────────────────────────────────────────

/// **A child run is NOT charged to the actor's hourly execution budget.**
///
/// Recorded here as a round trip rather than as a comment, because the whole
/// reason the ledger is a separate table is that recording children in
/// `workflow_executions` would bill one parent run twice.
#[tokio::test]
async fn a_recorded_child_run_does_not_move_the_actors_execution_budget() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let parent_exec = seed_live_execution(&pool, &t, false).await;

    let repo = talos_actor_repository::ActorRepository::new(pool.clone());
    let before = repo
        .count_executions_last_hour(t.actor)
        .await
        .expect("count before");

    let (parent, dispatcher) = parent_engine(&pool, &t, serde_json::json!({ "ok": true }));
    parent
        .execute_subworkflow_graph(
            t.child_workflow,
            serde_json::json!({}),
            dispatcher,
            None,
            ChildRunOrigin::Node {
                execution_id: parent_exec,
                node_id: Uuid::new_v4(),
                kind: talos_workflow_engine_core::ChildDispatchKind::SubWorkflow,
            },
        )
        .await
        .expect("the child runs");

    // The ledger row exists …
    let ledger_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_workflow_runs")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(ledger_rows, 1);
    // … and the budget did not move.
    assert_eq!(
        repo.count_executions_last_hour(t.actor)
            .await
            .expect("count after"),
        before,
        "a child run must not be charged to the actor's hourly execution budget — \
         the parent's run was budgeted when it was created"
    );
}

/// Every `ChildDispatchKind` spelling must satisfy the table's CHECK. The
/// enum and the constraint are two lists of the same thing, and this is what
/// keeps them from drifting.
#[tokio::test]
async fn every_dispatch_kind_spelling_satisfies_the_check_constraint() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let exec = seed_live_execution(&pool, &t, false).await;

    for kind in talos_workflow_engine_core::ChildDispatchKind::ALL {
        sqlx::query(
            "INSERT INTO sub_workflow_runs \
                 (parent_execution_id, parent_workflow_id, parent_node_id, dispatch_kind, \
                  child_workflow_id, user_id, depth, started_at, completed_at, status, \
                  duration_ms) \
             VALUES ($1, $2, 'n1', $3, $4, $5, 1, NOW(), NOW(), 'completed', 1)",
        )
        .bind(exec)
        .bind(t.parent_workflow)
        .bind(kind.as_str())
        .bind(t.child_workflow)
        .bind(t.user)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "dispatch_kind '{}' rejected by the CHECK: {e}",
                kind.as_str()
            )
        });
    }

    // …and a kind the ledger does NOT record must be refused, so the constraint
    // cannot quietly acquire a value nothing writes.
    for kind in talos_child_run_ledger::UNRECORDED_DISPATCH_KINDS {
        let refused = sqlx::query(
            "INSERT INTO sub_workflow_runs \
                 (parent_execution_id, parent_workflow_id, parent_node_id, dispatch_kind, \
                  child_workflow_id, user_id, depth, started_at, completed_at, status, \
                  duration_ms) \
             VALUES ($1, $2, 'n1', $3, $4, $5, 1, NOW(), NOW(), 'completed', 1)",
        )
        .bind(exec)
        .bind(t.parent_workflow)
        .bind(*kind)
        .bind(t.child_workflow)
        .bind(t.user)
        .execute(&pool)
        .await;
        assert!(
            refused.is_err(),
            "'{kind}' is documented as NOT recorded by P1; the CHECK must refuse it"
        );
    }
}

/// A ledger failure must be SILENT to the workflow and LOUD to the operator.
///
/// The first half is the design rule: `ChildRunRecorder::record` returns `()`,
/// so a failure has nowhere to go. The second half is what stops that rule
/// from becoming a hole — a dropped write is a child run that, to every
/// reader, never happened, and the counter is the only thing that can say so.
///
/// This drives the REAL `PostgresChildRunRecorder` against a CLOSED pool.
/// Check 58 proves a metric has an increment SITE; its own stated limit is
/// that it cannot prove anything reaches it. This does.
///
/// MUTATION that turns it red: delete the `child_run_record_failures_total`
/// increment in `PostgresChildRunRecorder::record`.
#[tokio::test]
async fn a_failed_ledger_write_is_swallowed_but_counted() {
    use talos_workflow_engine_core::{
        ChildDispatchKind, ChildRunRecord, ChildRunRecorder, ChildRunStatus,
    };

    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics registry"));
    let before = talos_metrics::global()
        .expect("metrics wired")
        .child_run_record_failures_total
        .with_label_values(&["acquire"])
        .get();

    let (pool, _db) = common::isolated_db_pool().await;
    pool.close().await;

    // Must NOT panic and must NOT return an error — there is no error type.
    PostgresChildRunRecorder::new(pool)
        .record(ChildRunRecord {
            parent_execution_id: Uuid::new_v4(),
            parent_workflow_id: Uuid::new_v4(),
            parent_node_id: "n1".into(),
            dispatch_kind: ChildDispatchKind::SubWorkflow,
            child_workflow_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            actor_id: None,
            depth: 1,
            started_at_unix_ms: 1_700_000_000_000,
            duration_ms: 5,
            status: ChildRunStatus::Completed,
            error_class: None,
        })
        .await;

    let after = talos_metrics::global()
        .expect("metrics wired")
        .child_run_record_failures_total
        .with_label_values(&["acquire"])
        .get();
    assert!(
        after > before,
        "a dropped ledger write must move talos_child_run_record_failures_total \
         {{reason=\"acquire\"}} — otherwise the silence is complete"
    );
}

// ── #768: who a SYNC invocation runs as ─────────────────────────────────────
//
// `call_workflow` and `bulk_trigger_workflow` built their engine with
// `with_effective_actor(None, wf_record.actor_id)` under a check-56 opt-out
// whose stated reason described `test_workflow`, a different handler. For an
// UNBOUND workflow that resolved to no actor at all, while the BEFORE INSERT
// trigger `trg_set_default_actor` stamped the user's Default actor on the
// execution ROW — the row said Default, the engine ran as nobody. The ledger
// is where "as nobody" is legible after the fact: `sub_workflow_runs.actor_id`
// takes the engine's binding, so the whole disagreement lands in one column.
//
// These tests drive the EXTRACTED resolver
// (`talos_mcp_handlers::utils::resolve_sync_call_effective_actor`) and the REAL
// ledger chokepoint. They cannot drive the handler bodies — `handle_call_workflow`
// is private, needs an `McpState` and dispatches over NATS. The guard against a
// call-site revert is structural instead: both opt-out markers are GONE, so
// lint check 56 fails on any reintroduced `with_effective_actor(None, …)` in
// `talos-mcp-handlers/src`. That mutation was performed and is recorded in
// AGENT_NOTES.md.

/// Seed an UNBOUND workflow (`actor_id IS NULL`) — the population this is
/// about. Measured on the reference fleet 2026-09-06: 6 of 36 workflows,
/// every one a `stress-*` draft, so the defect is LATENT for production
/// workflows and this is the shape that exercises it.
async fn seed_unbound_workflow(pool: &sqlx::PgPool, t: &Seeded) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json, actor_id) \
         VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb, NULL)",
    )
    .bind(id)
    .bind(t.user)
    .bind(t.org)
    .bind(format!("unbound-{id}"))
    .execute(pool)
    .await
    .expect("seed unbound workflow");
    id
}

/// An unbound workflow invoked SYNCHRONOUSLY must run as the user's default
/// actor — the same answer `trigger_workflow` has given since Phase D1, and
/// the same answer the execution-row trigger has been stamping all along.
///
/// Three arms, because "it returned something" is not the claim:
/// the unbound case resolves to the DEFAULT actor; a workflow with its own
/// actor keeps that actor (the resolver must not overwrite a real binding with
/// the default); and the answer is STABLE across calls, since the fallback
/// creates the default actor on first use and a second call that minted a
/// second one would give the same workflow two identities.
#[tokio::test]
async fn an_unbound_sync_call_resolves_the_users_default_actor() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let unbound = seed_unbound_workflow(&pool, &t).await;

    let workflow_repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let actor_repo = talos_actor_repository::ActorRepository::new(pool.clone());

    // No default actor exists yet — the fallback must create one, which is the
    // Phase-D1 behaviour and the reason this is not simply a lookup.
    let pre: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM actors WHERE user_id = $1 AND is_default")
            .bind(t.user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pre, 0, "fixture must start with no default actor");

    let resolved = talos_mcp_handlers::utils::resolve_sync_call_effective_actor(
        &workflow_repo,
        &actor_repo,
        &pool,
        None, // the unbound workflow's own actor_id
        t.user,
        "{}",
        None,
    )
    .await
    .expect("an unbound workflow must resolve, not refuse");

    let actor = resolved.expect("the gate never returns None on success (Phase D1 fallback)");
    let (owner, is_default): (Uuid, bool) =
        sqlx::query_as("SELECT user_id, is_default FROM actors WHERE id = $1")
            .bind(actor)
            .fetch_one(&pool)
            .await
            .expect("the resolved actor must exist");
    assert_eq!(owner, t.user, "the resolved actor belongs to the caller");
    assert!(
        is_default,
        "an unbound workflow runs as the user's DEFAULT actor — the same principal \
         trg_set_default_actor has been stamping on the execution row all along"
    );

    // A workflow WITH its own actor keeps it. Without this the assertion above
    // is satisfied by a resolver that ignores its argument.
    let bound = talos_mcp_handlers::utils::resolve_sync_call_effective_actor(
        &workflow_repo,
        &actor_repo,
        &pool,
        Some(t.actor),
        t.user,
        "{}",
        None,
    )
    .await
    .expect("a bound workflow resolves")
    .expect("bound actor");
    assert_eq!(
        bound, t.actor,
        "a workflow's own actor must not be replaced by the default"
    );

    // Stable: a second call must not mint a second default identity.
    let again = talos_mcp_handlers::utils::resolve_sync_call_effective_actor(
        &workflow_repo,
        &actor_repo,
        &pool,
        None,
        t.user,
        "{}",
        None,
    )
    .await
    .expect("resolves")
    .expect("actor");
    assert_eq!(
        again, actor,
        "the default-actor fallback must be idempotent"
    );

    let _ = unbound; // the row exists so the fixture is honest; the gate reads the actor, not the row
}

/// The gate FAILS CLOSED, and the refusal reaches the caller as an MCP error
/// rather than as a silent `None`.
///
/// An archived actor is an IRREVERSIBLE terminal state that `trigger_workflow`
/// has always refused. Before #768 the sync path did not consult the gate at
/// all, so the same workflow ran through `call_workflow` and was refused
/// through `trigger_workflow` — the asymmetry, in one sentence.
#[tokio::test]
async fn an_archived_actor_refuses_the_sync_call_instead_of_binding_nobody() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    sqlx::query("UPDATE actors SET status = 'archived' WHERE id = $1")
        .bind(t.actor)
        .execute(&pool)
        .await
        .expect("archive the actor");

    let workflow_repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let actor_repo = talos_actor_repository::ActorRepository::new(pool.clone());

    let err = talos_mcp_handlers::utils::resolve_sync_call_effective_actor(
        &workflow_repo,
        &actor_repo,
        &pool,
        Some(t.actor),
        t.user,
        "{}",
        None,
    )
    .await
    .expect_err("an archived actor must refuse");
    // `mcp_error` returns the refusal as an MCP TOOL RESULT (`isError: true`
    // plus `errorCode`), not as a JSON-RPC `error` object — so clients render
    // the real message. Assert on the shape the caller actually sees.
    let result = err
        .result
        .as_ref()
        .expect("a refusal carries a tool result");
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(result["errorCode"], -32000, "{result}");
    let msg = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        msg.contains("archived"),
        "the refusal must carry the trigger path's own wording, not a generic one: {msg}"
    );
}

/// What the binding COSTS, read back out of the ledger.
///
/// The engine bound to the resolved actor records it; the engine built the way
/// an unresolved binding used to leave it records `actor_id: NULL` — a child
/// run with no tenancy principal, on a run whose execution row says Default.
/// This is the consequence #768 removes, pinned as a fact rather than as prose.
#[tokio::test]
async fn the_ledger_records_the_actor_the_engine_was_bound_to() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;

    let workflow_repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let actor_repo = talos_actor_repository::ActorRepository::new(pool.clone());
    let resolved = talos_mcp_handlers::utils::resolve_sync_call_effective_actor(
        &workflow_repo,
        &actor_repo,
        &pool,
        None,
        t.user,
        "{}",
        None,
    )
    .await
    .expect("resolves")
    .expect("the default actor");

    // (a) bound to the gate's answer.
    let bound_exec = seed_live_execution(&pool, &t, false).await;
    let (parent, dispatcher) =
        parent_engine_bound_to(&pool, &t, serde_json::json!({ "ok": true }), Some(resolved));
    parent
        .execute_subworkflow_graph(
            t.child_workflow,
            serde_json::json!({}),
            dispatcher,
            None,
            ChildRunOrigin::Node {
                execution_id: bound_exec,
                node_id: Uuid::new_v4(),
                kind: talos_workflow_engine_core::ChildDispatchKind::SubWorkflow,
            },
        )
        .await
        .expect("the child runs");

    // (b) the pre-#768 shape: no actor bound at all.
    let unbound_exec = seed_live_execution(&pool, &t, false).await;
    let (parent, dispatcher) =
        parent_engine_bound_to(&pool, &t, serde_json::json!({ "ok": true }), None);
    parent
        .execute_subworkflow_graph(
            t.child_workflow,
            serde_json::json!({}),
            dispatcher,
            None,
            ChildRunOrigin::Node {
                execution_id: unbound_exec,
                node_id: Uuid::new_v4(),
                kind: talos_workflow_engine_core::ChildDispatchKind::SubWorkflow,
            },
        )
        .await
        .expect("the child runs");

    let read = |exec: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<Uuid>>(
                "SELECT actor_id FROM sub_workflow_runs WHERE parent_execution_id = $1",
            )
            .bind(exec)
            .fetch_one(&pool)
            .await
            .expect("one ledger row per dispatch")
        }
    };

    assert_eq!(
        read(bound_exec).await,
        Some(resolved),
        "the ledger must record the actor the gate resolved — this is what the sync \
         path now binds"
    );
    assert_eq!(
        read(unbound_exec).await,
        None,
        "and this is what it recorded before #768: a child run attributed to nobody, \
         beside an execution row the trg_set_default_actor trigger had stamped with \
         the user's Default actor"
    );
}
