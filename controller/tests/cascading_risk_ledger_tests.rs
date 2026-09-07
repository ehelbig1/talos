//! The cascading-failure check reads the child-run ledger — RFC 0012 P3.
//!
//! `get_workflow_risk_assessment`'s `high_failure_sub_workflow` check read
//! `workflow_executions` and nothing else, and a sub-workflow records no row
//! there. So every child landed in `sub_workflows_unmeasurable` and the
//! HIGH-severity risk could not fire for any of them.
//!
//! **`main_*` is the FALSIFICATION, and it still passes after the fix — on
//! purpose.** It asserts a fact about the two READS, not about the decision:
//! the execution read is blind to a child with three recorded, all-failed runs,
//! and the ledger read sees them. That fact is what made the pre-P3 verdict
//! wrong and is what the new verdict is built on, so it is a CONTROL, not a
//! reproducer. The behaviour change is pinned by the `p3_*` tests and by the
//! pure-decision tests in `talos_analytics_repository::cascading_risk`, each of
//! which names the mutation that turns it red.
//!
//! Everything here drives real production code against a real Postgres: the
//! real `get_risk_exec_counts_for_ids`, the real
//! `child_ledger_evidence_since_for` (its floor read, its window clamp, its
//! absent-key contract), and the real shared `classify_sub_workflow_risk`. A
//! pure test cannot cover the half that matters — which rows the grouped query
//! returns, and what an absence means.
//!
//! `ChildRunLedger::since` is process-cached and this binary drives isolated
//! databases from one process, so every ledger read goes through
//! `evidence_for`, which holds a lock across reset→read.
//!
//! DB tests on the `common` harness, so CTRL_TESTS and not TC_TESTS (64b).

mod common;

use chrono::{DateTime, Duration, Utc};
use sqlx::{Pool, Postgres};
use talos_analytics_repository::{
    classify_sub_workflow_risk, risk_window_start, AnalyticsRepository, RiskPopulation,
    SubWorkflowRiskVerdict, UnmeasurableReason, LEDGER_MIN_RUNS,
};
use talos_child_run_ledger::ChildRunLedger;
use uuid::Uuid;

/// Serialises every read that touches the PROCESS-WIDE `since()` cache. Same
/// harness fact `child_readiness_ledger_tests` records: without it a test can
/// reset the cache and then read a sibling database's floor.
static LEDGER_FLOOR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn evidence_for(
    repo: &AnalyticsRepository,
    user: Uuid,
    ids: &[Uuid],
) -> std::collections::HashMap<Uuid, talos_analytics_repository::ChildLedgerEvidence> {
    let _guard = LEDGER_FLOOR_LOCK.lock().await;
    ChildRunLedger::reset_since_cache();
    repo.child_ledger_evidence_since_for(user, ids, risk_window_start(Utc::now()))
        .await
        .expect("ledger evidence")
}

/// The whole production path for one child: the real execution read, the real
/// ledger read, the real shared decision.
async fn verdict_for(
    repo: &AnalyticsRepository,
    user: Uuid,
    child: Uuid,
) -> SubWorkflowRiskVerdict {
    let exec = repo
        .get_risk_exec_counts_for_ids(&[child], user)
        .await
        .expect("risk exec counts");
    let ledger = evidence_for(repo, user, &[child]).await;
    classify_sub_workflow_risk(exec.get(&child).copied(), ledger.get(&child).copied())
}

/// `workflow_executions.actor_id` is NOT NULL, so a direct run needs an actor.
async fn seed_actor(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'p3-risk-actor')")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

async fn seed_execution(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    actor_id: Uuid,
    wf: Uuid,
    status: &str,
    started_at: DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, actor_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $6 + interval '1 second')",
    )
    .bind(Uuid::new_v4())
    .bind(wf)
    .bind(user_id)
    .bind(actor_id)
    .bind(status)
    .bind(started_at)
    .execute(pool)
    .await
    .expect("seed execution");
}

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'p3 risk')",
    )
    .bind(id)
    .bind(format!("p3-risk-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user_id: Uuid, name: &str, graph: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, $4, 'talos://t', 'published', true)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(graph)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_child_run(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    parent_wf: Uuid,
    child_wf: Uuid,
    status: &str,
    hours_ago: i64,
) {
    sqlx::query(
        "INSERT INTO sub_workflow_runs \
             (parent_execution_id, parent_workflow_id, parent_node_id, dispatch_kind, \
              child_workflow_id, user_id, depth, started_at, completed_at, status, duration_ms) \
         VALUES ($1, $2, 'child', 'judge', $3, $4, 1, $5, $5 + interval '80 milliseconds', $6, 80)",
    )
    .bind(Uuid::new_v4())
    .bind(parent_wf)
    .bind(child_wf)
    .bind(user_id)
    .bind(Utc::now() - Duration::hours(hours_ago))
    .bind(status)
    .execute(pool)
    .await
    .expect("seed child run");
}

/// FALSIFICATION / CONTROL (A1). Three RECORDED, ALL-FAILED child runs inside the
/// cascading check's own 7-day window, and the read the check is built on
/// returns NOTHING for that child — so the check lands it in
/// `sub_workflows_unmeasurable` and pushes no `high_failure_sub_workflow`
/// risk, exactly as if the child had never run.
#[tokio::test]
async fn main_the_risk_read_is_blind_to_a_totally_failing_child() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let child = seed_workflow(&pool, user, "p3-child", r#"{"nodes":[],"edges":[]}"#).await;
    let parent = seed_workflow(
        &pool,
        user,
        "p3-parent",
        &format!(
            r#"{{"nodes":[{{"id":"j","type":"system:judge","data":{{"judge_workflow_id":"{child}"}}}}],"edges":[]}}"#
        ),
    )
    .await;

    for h in 1..=3 {
        seed_child_run(&pool, user, parent, child, "failed", h).await;
    }

    let counts = repo
        .get_risk_exec_counts_for_ids(&[child], user)
        .await
        .expect("risk exec counts");
    println!("MEASURED: get_risk_exec_counts_for_ids -> {counts:?}");

    let ledger = talos_child_run_ledger::ChildRunLedger::new(pool.clone());
    talos_child_run_ledger::ChildRunLedger::reset_since_cache();
    let stats = ledger
        .child_run_stats_since(&[child], user, Utc::now() - Duration::days(7))
        .await
        .expect("ledger stats");
    println!("MEASURED: ledger stats -> {stats:?}");

    assert!(
        counts.get(&child).is_none(),
        "the cascading check's only input sees the child"
    );
    let s = stats.get(&child).expect("ledger has the child");
    assert_eq!((s.runs, s.failed), (3, 3));
}

/// FALSIFICATION (new finding). The monitor's threshold row read is
/// `let webhook: String = row.get("notification_webhook")`, and the column is
/// nullable by design. Drive the monitor's EXACT statement and the EXACT
/// decode over a row `set_workflow_sla_threshold` can create today.
#[tokio::test]
async fn main_a_null_webhook_panics_the_monitors_threshold_decode() {
    use sqlx::Row;
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user, "p3-sla", r#"{"nodes":[],"edges":[]}"#).await;
    sqlx::query(
        "INSERT INTO workflow_sla_thresholds (workflow_id, user_id, p95_latency_ms, notification_webhook) \
         VALUES ($1, $2, 1000, NULL)",
    )
    .bind(wf)
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed threshold with no webhook");

    let rows = sqlx::query(
        "SELECT t.workflow_id, t.user_id, t.p95_latency_ms, \
                t.success_rate_pct::float8 AS success_rate_pct, \
                t.notification_webhook \
         FROM workflow_sla_thresholds t",
    )
    .fetch_all(&pool)
    .await
    .expect("threshold load");
    assert_eq!(rows.len(), 1);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _webhook: String = rows[0].get("notification_webhook");
    }))
    .is_err();
    println!("MEASURED: row.get::<String,_>(\"notification_webhook\") panicked = {panicked}");
    assert!(
        panicked,
        "the monitor's decode did NOT panic on a NULL webhook"
    );
}

async fn seed_parent_and_child(pool: &Pool<Postgres>, user: Uuid) -> (Uuid, Uuid) {
    let child = seed_workflow(pool, user, "p3-child", r#"{"nodes":[],"edges":[]}"#).await;
    let parent = seed_workflow(
        pool,
        user,
        "p3-parent",
        &format!(
            r#"{{"nodes":[{{"id":"j","type":"system:judge","data":{{"judge_workflow_id":"{child}"}}}}],"edges":[]}}"#
        ),
    )
    .await;
    (parent, child)
}

/// AT the floor, with no execution rows, the ledger MEASURES the child and the
/// HIGH-severity risk fires for the first time.
///
/// MUTATION that turns it red: return `Unmeasurable` whenever the execution
/// total is 0 (the pre-P3 behaviour).
#[tokio::test]
async fn p3_a_totally_failing_child_now_breaches_from_the_ledger() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let (parent, child) = seed_parent_and_child(&pool, user).await;
    for h in 1..=LEDGER_MIN_RUNS {
        seed_child_run(&pool, user, parent, child, "failed", h).await;
    }

    let SubWorkflowRiskVerdict::Measured(m) = verdict_for(&repo, user, child).await else {
        panic!("a child at the floor must be measurable");
    };
    assert_eq!(m.population, RiskPopulation::ChildRuns);
    assert_eq!((m.failed, m.total), (LEDGER_MIN_RUNS, LEDGER_MIN_RUNS));
    assert!(m.breaches(), "100% failure must clear the 20% bar");
    assert!(
        m.ledger_since.is_some(),
        "a measured verdict must carry the floor it rests on"
    );
}

/// ONE BELOW the floor the child stays unmeasurable — and says so WITH the
/// count and the floor, never as a bare absence.
///
/// MUTATION: `LEDGER_MIN_RUNS = 1`.
#[tokio::test]
async fn p3_below_the_floor_the_child_is_unmeasurable_with_numbers() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let (parent, child) = seed_parent_and_child(&pool, user).await;
    for h in 1..LEDGER_MIN_RUNS {
        seed_child_run(&pool, user, parent, child, "failed", h).await;
    }

    let SubWorkflowRiskVerdict::Unmeasurable(u) = verdict_for(&repo, user, child).await else {
        panic!("below the floor the child must not be judged");
    };
    assert_eq!(u.reason, UnmeasurableReason::BelowLedgerFloor);
    assert_eq!(u.child_runs, LEDGER_MIN_RUNS - 1);
    assert!(u.ledger_since.is_some());
    assert!(u.note().contains("not called healthy"));
}

/// An EMPTY ledger renders UNKNOWN, not "no runs". This is the state every
/// deployment is in before its first child run.
///
/// MUTATION: drop the `ledger_since.is_none()` arm from the classifier.
#[tokio::test]
async fn p3_an_empty_ledger_is_unknown_not_zero() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let (_parent, child) = seed_parent_and_child(&pool, user).await;

    let SubWorkflowRiskVerdict::Unmeasurable(u) = verdict_for(&repo, user, child).await else {
        panic!("an empty ledger cannot measure anything");
    };
    assert_eq!(u.reason, UnmeasurableReason::LedgerEmpty);
    assert!(u.note().contains("UNKNOWN"));
}

/// HYBRID: a workflow that is BOTH dispatched as a child and triggered
/// directly is judged over the UNION, and the ledger's contribution is
/// disclosed.
///
/// MUTATION: drop the ledger half of the union — the rate becomes 100% and the
/// finding changes severity on evidence it does not have.
#[tokio::test]
async fn p3_a_hybrid_child_is_judged_over_both_tables() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let (parent, child) = seed_parent_and_child(&pool, user).await;
    // One direct run, failed.
    let actor = seed_actor(&pool, user).await;
    seed_execution(
        &pool,
        user,
        actor,
        child,
        "failed",
        Utc::now() - Duration::hours(2),
    )
    .await;
    // Nine dispatched runs, all fine.
    for h in 1..=9 {
        seed_child_run(&pool, user, parent, child, "completed", h).await;
    }

    let SubWorkflowRiskVerdict::Measured(m) = verdict_for(&repo, user, child).await else {
        panic!("a hybrid child is measurable from either side");
    };
    assert_eq!(m.population, RiskPopulation::Both);
    assert_eq!((m.failed, m.total), (1, 10));
    assert!(
        !m.breaches(),
        "10% over the union must not fire a 20% bar; the execution row alone would read 100%"
    );
    let note = m.population_note().expect("the split is disclosed");
    assert!(note.contains("9 child run(s)"));
}

/// The ledger read is scoped to the CALLER. A child run recorded for another
/// tenant must read as UNKNOWN here, never as evidence.
///
/// MUTATION: drop `AND user_id = $2` from `child_run_stats_since`.
#[tokio::test]
async fn p3_another_tenants_child_runs_are_not_evidence() {
    let (pool, _db) = common::isolated_db_pool().await;
    let mine = seed_user(&pool).await;
    let theirs = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let (their_parent, shared_child) = seed_parent_and_child(&pool, theirs).await;
    for h in 1..=(LEDGER_MIN_RUNS + 2) {
        seed_child_run(&pool, theirs, their_parent, shared_child, "failed", h).await;
    }

    // The other tenant CAN measure it.
    let SubWorkflowRiskVerdict::Measured(_) = verdict_for(&repo, theirs, shared_child).await else {
        panic!("the owning tenant must see its own child runs");
    };
    // I cannot.
    let SubWorkflowRiskVerdict::Unmeasurable(u) = verdict_for(&repo, mine, shared_child).await
    else {
        panic!("another tenant's child runs must not be evidence for me");
    };
    assert_eq!(u.child_runs, 0);
    assert_eq!(u.reason, UnmeasurableReason::NoRunsRecorded);
}

/// The ledger window is the CHECK's window. A run 30 days old is inside
/// readiness's window and outside this one, and must not be counted here.
///
/// MUTATION: pass `readiness_window_start` instead of `risk_window_start`.
#[tokio::test]
async fn p3_the_ledger_read_uses_the_checks_own_seven_day_window() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let (parent, child) = seed_parent_and_child(&pool, user).await;
    for d in [10i64, 12, 14] {
        seed_child_run(&pool, user, parent, child, "failed", d * 24).await;
    }

    let ev = evidence_for(&repo, user, &[child]).await;
    let ev = ev
        .get(&child)
        .copied()
        .expect("every id asked about is present");
    assert_eq!(
        ev.runs, 0,
        "runs older than seven days are outside the cascading check's window"
    );
    // …and the floor still travels, so the zero is legible.
    assert!(ev.ledger_since.is_some());
}
