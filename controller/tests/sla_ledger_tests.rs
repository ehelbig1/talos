//! The SLA window is measured over BOTH populations — RFC 0012 P3.
//!
//! Two defects are pinned here and each was MEASURED on the pre-fix tree
//! before anything was written (see `AGENT_NOTES.md`):
//!
//! 1. **A threshold on a sub-workflow was silently inert.** The 5-min breach
//!    monitor and the 15-min degradation loop both read `workflow_executions`
//!    alone, and a child records no row there, so `total == 0 => continue`
//!    fired on every tick forever.
//! 2. **A NULL `notification_webhook` PANICKED the monitor.** It decoded that
//!    column with `sqlx::Row::get::<String, _>`, the column is nullable by
//!    design, and `set_workflow_sla_threshold` stores NULL for the documented
//!    API-polling configuration. The panic is inside a spawned task, so ONE
//!    such row ended the SLA monitor for the whole process lifetime.
//!
//! **The loops themselves are UNDRIVABLE from a test** and that is stated
//! rather than worked around: `controller/src/bootstrap/background.rs` is
//! `mod bootstrap` inside `main.rs`, i.e. bin-private, so nothing in
//! `controller/tests/` can call `spawn_late_background_tasks`. What these tests
//! drive is everything the loops now delegate to — the real
//! `read_sla_window_sources` UNION statement against a real Postgres, the real
//! `decide_sla_breaches`, and the real threshold-row decode — which is exactly
//! why the decision was extracted in the first place. The residual gap (a
//! mutation to the loop's own wiring) is named in `AGENT_NOTES.md`.
//!
//! `common` (DATABASE_URL) harness, so CTRL_TESTS and not TC_TESTS (64b).

mod common;

use chrono::{DateTime, Duration, Utc};
use sqlx::{Pool, Postgres, Row};
use talos_analytics_repository::{
    decide_sla_breaches, read_sla_window_sources, SlaMetric, SlaNotEvaluated, SlaThresholds,
    LEDGER_MIN_RUNS, SLA_WINDOW_HOURS,
};
use talos_child_run_ledger::ChildRunLedger;
use uuid::Uuid;

/// The floor cache is PROCESS-WIDE and this binary drives isolated databases
/// from one process. Same harness fact `child_readiness_ledger_tests` records.
static LEDGER_FLOOR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'p3 sla')",
    )
    .bind(id)
    .bind(format!("p3-sla-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'p3-sla-actor')")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, '{\"nodes\":[],\"edges\":[]}', 'talos://t', 'published', true)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_execution(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    actor_id: Uuid,
    wf: Uuid,
    status: &str,
    started_at: DateTime<Utc>,
    duration_ms: i64,
) {
    #[allow(clippy::cast_precision_loss)]
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, actor_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $6 + make_interval(secs => $7::float8))",
    )
    .bind(Uuid::new_v4())
    .bind(wf)
    .bind(user_id)
    .bind(actor_id)
    .bind(status)
    .bind(started_at)
    .bind(duration_ms as f64 / 1000.0)
    .execute(pool)
    .await
    .expect("seed execution");
}

/// An execution that is still RUNNING: `completed_at IS NULL`.
async fn seed_running_execution(pool: &Pool<Postgres>, user_id: Uuid, actor_id: Uuid, wf: Uuid) {
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
         VALUES ($1, $2, $3, $4, 'running', NOW() - interval '1 hour')",
    )
    .bind(Uuid::new_v4())
    .bind(wf)
    .bind(user_id)
    .bind(actor_id)
    .execute(pool)
    .await
    .expect("seed running execution");
}

async fn seed_child_run(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    parent_wf: Uuid,
    child_wf: Uuid,
    status: &str,
    hours_ago: i64,
    duration_ms: i64,
) {
    sqlx::query(
        "INSERT INTO sub_workflow_runs \
             (parent_execution_id, parent_workflow_id, parent_node_id, dispatch_kind, \
              child_workflow_id, user_id, depth, started_at, completed_at, status, duration_ms) \
         VALUES ($1, $2, 'child', 'sub_workflow', $3, $4, 1, $5, \
                 $5 + make_interval(secs => $6::float8), $7, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(parent_wf)
    .bind(child_wf)
    .bind(user_id)
    .bind(Utc::now() - Duration::hours(hours_ago))
    .bind(duration_ms)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed child run");
}

async fn sources_for(
    pool: &Pool<Postgres>,
    wf: Uuid,
    user: Uuid,
) -> talos_analytics_repository::SlaWindowSources {
    let _guard = LEDGER_FLOOR_LOCK.lock().await;
    ChildRunLedger::reset_since_cache();
    read_sla_window_sources(pool, wf, user, SLA_WINDOW_HOURS)
        .await
        .expect("sla window sources")
}

// ── the child population ────────────────────────────────────────────────────

/// The P3 fix, end to end against a real database: a threshold on a workflow
/// that ONLY runs as a sub-workflow now reaches a verdict.
///
/// MUTATION that turns it red: drop the `sub_workflow_runs` half of the UNION.
#[tokio::test]
async fn a_threshold_on_a_sub_workflow_is_no_longer_inert() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let parent = seed_workflow(&pool, user, "p3-sla-parent").await;
    let child = seed_workflow(&pool, user, "p3-sla-child").await;
    for h in 1..=10 {
        let status = if h <= 5 { "failed" } else { "completed" };
        seed_child_run(&pool, user, parent, child, status, h, 9_000).await;
    }

    let sources = sources_for(&pool, child, user).await;
    assert_eq!(
        sources.executions.total, 0,
        "a child leaves no execution row"
    );
    assert_eq!(sources.child_runs.total, 10);
    assert_eq!(sources.combined.total, 10);
    assert!(sources.ledger_since.is_some());

    let decision = decide_sla_breaches(
        &sources,
        &SlaThresholds {
            p95_latency_ms: Some(5_000),
            success_rate_pct: Some(99.0),
        },
    );
    assert!(decision.not_evaluated.is_none());
    let metrics: Vec<_> = decision.breaches.iter().map(|b| b.metric).collect();
    assert!(metrics.contains(&SlaMetric::SuccessRatePct));
    assert!(metrics.contains(&SlaMetric::P95LatencyMs));
    assert!(sources
        .population_note()
        .expect("the split is disclosed")
        .contains("10 child run(s)"));
}

/// BELOW the floor an alerter must not page. One failed child run is a 0%
/// success rate, and a p95 over n=1 is that run's latency.
///
/// MUTATION: `LEDGER_MIN_RUNS = 1`.
#[tokio::test]
async fn a_child_only_population_below_the_floor_pages_nobody() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let parent = seed_workflow(&pool, user, "p3-sla-parent").await;
    let child = seed_workflow(&pool, user, "p3-sla-child").await;
    for h in 1..LEDGER_MIN_RUNS {
        seed_child_run(&pool, user, parent, child, "failed", h, 600_000).await;
    }

    let sources = sources_for(&pool, child, user).await;
    let decision = decide_sla_breaches(
        &sources,
        &SlaThresholds {
            p95_latency_ms: Some(1_000),
            success_rate_pct: Some(99.0),
        },
    );
    assert!(!decision.fired());
    assert_eq!(
        decision.not_evaluated,
        Some(SlaNotEvaluated::BelowLedgerFloor)
    );
}

/// A HYBRID workflow is judged over the union, and the combined p95 comes out
/// of the SAME statement rather than being averaged from two percentiles.
///
/// MUTATION: compute `combined` in Rust as `executions + child_runs` with the
/// larger p95 — the assertion below is the ROLLUP's real percentile.
#[tokio::test]
async fn a_hybrid_workflow_is_judged_over_the_union() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let parent = seed_workflow(&pool, user, "p3-sla-parent").await;
    let child = seed_workflow(&pool, user, "p3-sla-child").await;
    // Two direct runs, both fast and successful.
    for h in 1..=2 {
        seed_execution(
            &pool,
            user,
            actor,
            child,
            "completed",
            Utc::now() - Duration::hours(h),
            100,
        )
        .await;
    }
    // Eight dispatched runs, two of them failed and all of them slow.
    for h in 1..=8 {
        let status = if h <= 2 { "failed" } else { "completed" };
        seed_child_run(&pool, user, parent, child, status, h, 10_000).await;
    }

    let sources = sources_for(&pool, child, user).await;
    assert_eq!(sources.executions.total, 2);
    assert_eq!(sources.child_runs.total, 8);
    assert_eq!(sources.combined.total, 10);
    assert_eq!(sources.combined.succeeded, 8);
    assert_eq!(sources.combined.success_rate_pct(), Some(80.0));
    // Eight of ten runs are 10 s, so the union's p95 is 10 s — not the
    // executions' 100 ms and not an average of the two percentiles.
    let p95 = sources.combined.p95_ms.expect("a union p95");
    assert!(
        (p95 - 10_000.0).abs() < 1.0,
        "combined p95 should be the union's, got {p95}"
    );
}

// ── the execution population, unchanged ─────────────────────────────────────

/// A workflow the ledger says nothing about is measured exactly as before,
/// and its response gains no key.
///
/// MUTATION: emit a population note unconditionally.
#[tokio::test]
async fn a_workflow_with_no_child_runs_is_measured_as_before() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let wf = seed_workflow(&pool, user, "p3-sla-plain").await;
    for h in 1..=4 {
        seed_execution(
            &pool,
            user,
            actor,
            wf,
            if h == 1 { "failed" } else { "completed" },
            Utc::now() - Duration::hours(h),
            100,
        )
        .await;
    }

    let sources = sources_for(&pool, wf, user).await;
    assert_eq!(sources.executions.total, 4);
    assert_eq!(sources.child_runs.total, 0);
    assert_eq!(sources.combined.succeeded, 3);
    assert!(!sources.ledger_contributed());
    assert!(sources.population_note().is_none());
}

/// The UNIFIED read uses the 5-min monitor's (stricter) denominator: an
/// execution still IN FLIGHT is not counted against the success rate.
///
/// This is the disagreement the two loops carried — `get_sla_window_stats` had
/// no `completed_at IS NOT NULL` — so this test pins which side won.
///
/// MUTATION: drop `AND completed_at IS NOT NULL` from the execution half.
#[tokio::test]
async fn an_in_flight_execution_is_not_a_failure() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let wf = seed_workflow(&pool, user, "p3-sla-inflight").await;
    seed_execution(
        &pool,
        user,
        actor,
        wf,
        "completed",
        Utc::now() - Duration::hours(1),
        100,
    )
    .await;
    seed_running_execution(&pool, user, actor, wf).await;

    let sources = sources_for(&pool, wf, user).await;
    assert_eq!(
        sources.executions.total, 1,
        "an open run is not in the SLA denominator"
    );
    assert_eq!(sources.combined.success_rate_pct(), Some(100.0));
}

/// The read is tenant-scoped on BOTH halves.
///
/// MUTATION: drop `AND user_id = $2` from either half of the UNION.
#[tokio::test]
async fn another_tenants_runs_are_not_in_my_window() {
    let (pool, _db) = common::isolated_db_pool().await;
    let mine = seed_user(&pool).await;
    let theirs = seed_user(&pool).await;
    let their_actor = seed_actor(&pool, theirs).await;
    let parent = seed_workflow(&pool, theirs, "p3-sla-parent").await;
    let shared = seed_workflow(&pool, theirs, "p3-sla-shared").await;
    seed_execution(
        &pool,
        theirs,
        their_actor,
        shared,
        "failed",
        Utc::now() - Duration::hours(1),
        100,
    )
    .await;
    for h in 1..=5 {
        seed_child_run(&pool, theirs, parent, shared, "failed", h, 100).await;
    }

    let theirs_sources = sources_for(&pool, shared, theirs).await;
    assert_eq!(theirs_sources.combined.total, 6);

    let mine_sources = sources_for(&pool, shared, mine).await;
    assert_eq!(mine_sources.executions.total, 0);
    assert_eq!(mine_sources.child_runs.total, 0);
    let decision = decide_sla_breaches(
        &mine_sources,
        &SlaThresholds {
            p95_latency_ms: None,
            success_rate_pct: Some(99.0),
        },
    );
    assert_eq!(decision.not_evaluated, Some(SlaNotEvaluated::NoRuns));
}

// ── the threshold row itself ────────────────────────────────────────────────

/// The DOCUMENTED API-polling configuration — a threshold with no webhook —
/// must decode. `sqlx::Row::get::<String, _>` PANICS on it, and the monitor's
/// loop is a spawned task, so one such row ended the alerter permanently.
///
/// This drives the monitor's EXACT statement and the fixed `try_get` decode.
///
/// MUTATION: change the decode back to `row.get::<String, _>(..)` — the
/// closure panics and the test fails.
#[tokio::test]
async fn a_threshold_with_no_webhook_decodes_instead_of_panicking() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user, "p3-sla-nohook").await;
    sqlx::query(
        "INSERT INTO workflow_sla_thresholds (workflow_id, user_id, p95_latency_ms, notification_webhook) \
         VALUES ($1, $2, 1000, NULL)",
    )
    .bind(wf)
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed threshold with no webhook");

    // The monitor's statement, verbatim.
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

    // The monitor's decode, verbatim.
    let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rows[0].try_get::<Option<String>, _>("notification_webhook")
    }));
    let webhook = decoded
        .expect("the decode must not panic")
        .expect("the decode must not error");
    assert!(webhook.is_none(), "an omitted webhook decodes to None");
}
