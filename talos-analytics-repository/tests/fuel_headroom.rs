// ci-store: migrated — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! Which rollup rows does the fuel-headroom DETECTOR count?
//!
//! `AnalyticsRepository::get_node_fuel_headroom` feeds the controller's
//! high-utilisation gauge (fleet-wide) and the fuel report (owner-scoped). Its
//! answers are properties of its SQL, so they are driven here against a
//! migrated Postgres:
//!
//! * a SUB-workflow row (synthetic execution id, no `workflow_executions` row)
//!   is counted;
//! * a TEST execution's row is not;
//! * a failed attempt's row is not (learners read completed rows only);
//! * a module-bound row (no `workflow_id`) is not;
//! * the ceiling is the latest row's, not the maximum;
//! * the owner filter returns only the caller's workflows.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (a MIGRATED database); skips with a
//! printed note when unset.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use talos_analytics_repository::{AnalyticsRepository, NodeFuelHeadroom};
use uuid::Uuid;

async fn pool_or_skip() -> Option<Pool<Postgres>> {
    let url = match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL to run fuel_headroom");
            return None;
        }
    };
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("TALOS_TEST_DATABASE_URL connect"),
    )
}

/// A user with the Default actor `workflow_executions` inserts resolve to.
async fn seed_user(pool: &Pool<Postgres>, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', $3)")
        .bind(id)
        .bind(format!("headroom-{tag}-{}@test.invalid", id.simple()))
        .bind(format!("headroom-{tag}"))
        .execute(pool)
        .await
        .expect("seed user");
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, is_default) \
         VALUES (gen_random_uuid(), $1, 'Default', 'network-node', true)",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed default actor");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, '', '{}')",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("{name}-{}", id.simple()))
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_execution(
    pool: &Pool<Postgres>,
    workflow_id: Uuid,
    user_id: Uuid,
    test: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, is_test_execution) \
         VALUES ($1, $2, $3, 'completed', $4)",
    )
    .bind(id)
    .bind(workflow_id)
    .bind(user_id)
    .bind(test)
    .execute(pool)
    .await
    .expect("seed execution");
    id
}

#[allow(clippy::too_many_arguments)]
async fn seed_rollup(
    pool: &Pool<Postgres>,
    workflow_id: Option<Uuid>,
    execution_id: Uuid,
    node: &str,
    fuel: i64,
    max_fuel: i64,
    minutes_ago: i64,
    outcome: &str,
) {
    sqlx::query(
        "INSERT INTO execution_cost_rollup \
           (workflow_id, execution_id, node_id, fuel_consumed, max_fuel, recorded_at, outcome) \
         VALUES ($1, $2, $3, $4, $5, NOW() - make_interval(mins => $6::int), $7)",
    )
    .bind(workflow_id)
    .bind(execution_id)
    .bind(node)
    .bind(fuel)
    .bind(max_fuel)
    .bind(minutes_ago as i32)
    .bind(outcome)
    .execute(pool)
    .await
    .expect("seed rollup row");
}

fn pairs_for(rows: &[NodeFuelHeadroom], workflows: &[Uuid]) -> Vec<(Uuid, String, i64, i64, i64)> {
    let mut v: Vec<_> = rows
        .iter()
        .filter(|r| workflows.contains(&r.workflow_id))
        .map(|r| {
            (
                r.workflow_id,
                r.node_label.clone(),
                r.samples,
                r.peak_fuel,
                r.current_ceiling,
            )
        })
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn the_detector_counts_production_and_subworkflow_rows_only() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let repo = AnalyticsRepository::new(pool.clone());
    let a = seed_user(&pool, "a").await;
    let b = seed_user(&pool, "b").await;
    let wf_a = seed_workflow(&pool, a, "headroom-a").await;
    let wf_b = seed_workflow(&pool, b, "headroom-b").await;

    // Counted: a production run, a sub-workflow run with NO execution row,
    // and the latest row, whose ceiling is the current one.
    let prod = seed_execution(&pool, wf_a, a, false).await;
    seed_rollup(&pool, Some(wf_a), prod, "n1", 500, 1_000, 120, "completed").await;
    seed_rollup(
        &pool,
        Some(wf_a),
        Uuid::new_v4(),
        "n1",
        900,
        1_000,
        60,
        "completed",
    )
    .await;
    let latest = seed_execution(&pool, wf_a, a, false).await;
    seed_rollup(&pool, Some(wf_a), latest, "n1", 100, 2_000, 10, "completed").await;

    // Not counted: a test execution, a failed attempt, a module-bound row.
    let test = seed_execution(&pool, wf_a, a, true).await;
    seed_rollup(&pool, Some(wf_a), test, "n1", 990, 1_000, 30, "completed").await;
    seed_rollup(&pool, Some(wf_a), prod, "n1", 1_999, 2_000, 5, "failed").await;
    seed_rollup(
        &pool,
        None,
        Uuid::new_v4(),
        "n1",
        1_500,
        2_000,
        5,
        "completed",
    )
    .await;

    let exec_b = seed_execution(&pool, wf_b, b, false).await;
    seed_rollup(&pool, Some(wf_b), exec_b, "m", 10, 100, 15, "completed").await;

    let expected_a = (wf_a, "n1".to_string(), 3, 900, 2_000);
    let expected_b = (wf_b, "m".to_string(), 1, 10, 100);
    let ours = [wf_a, wf_b];

    let scoped_a = repo
        .get_node_fuel_headroom(Some(a), 30, 100_000)
        .await
        .expect("owner-scoped read");
    assert_eq!(pairs_for(&scoped_a, &ours), vec![expected_a.clone()]);
    assert!(
        scoped_a.iter().all(|r| r.workflow_id != wf_b),
        "another user's workflow reached an owner-scoped read"
    );

    let scoped_b = repo
        .get_node_fuel_headroom(Some(b), 30, 100_000)
        .await
        .expect("owner-scoped read");
    assert_eq!(pairs_for(&scoped_b, &ours), vec![expected_b.clone()]);

    let fleet = repo
        .get_node_fuel_headroom(None, 30, 100_000)
        .await
        .expect("fleet-wide read");
    let mut both = vec![expected_a, expected_b];
    both.sort();
    assert_eq!(pairs_for(&fleet, &ours), both);
}

// ───────────────────────────────────────────────────────────────────────────
// Configured limits (2026-10-03): a node at the threshold whose limit was
// raised since its last run.
// ───────────────────────────────────────────────────────────────────────────

fn graph_with_limit(node: &str, limit: i64) -> String {
    serde_json::json!({
        "nodes": [{"id": node, "type": Uuid::new_v4().to_string(), "data": {"max_fuel": limit}}],
        "edges": []
    })
    .to_string()
}

async fn set_draft(pool: &Pool<Postgres>, workflow_id: Uuid, graph: &str) {
    sqlx::query("UPDATE workflows SET graph_json = $2 WHERE id = $1")
        .bind(workflow_id)
        .bind(graph)
        .execute(pool)
        .await
        .expect("set draft graph");
}

async fn publish(pool: &Pool<Postgres>, user: Uuid, workflow_id: Uuid, graph: &str) {
    sqlx::query(
        "INSERT INTO workflow_versions \
           (id, workflow_id, version_number, graph_json, is_active, published_by) \
         VALUES (gen_random_uuid(), $1, 1, $2::jsonb, true, $3)",
    )
    .bind(workflow_id)
    .bind(graph)
    .bind(user)
    .execute(pool)
    .await
    .expect("publish a version");
}

/// A node at 90% of the ceiling its one run was held to.
async fn seed_hot_node(pool: &Pool<Postgres>, user: Uuid, name: &str) -> Uuid {
    let wf = seed_workflow(pool, user, name).await;
    let exec = seed_execution(pool, wf, user, false).await;
    seed_rollup(
        pool,
        Some(wf),
        exec,
        "compose",
        9_000_000,
        10_000_000,
        5,
        "completed",
    )
    .await;
    wf
}

fn row_for(rows: &[NodeFuelHeadroom], workflow: Uuid) -> &NodeFuelHeadroom {
    rows.iter()
        .find(|r| r.workflow_id == workflow)
        .expect("the seeded pair is in the rows")
}

#[tokio::test]
async fn a_limit_raised_since_the_last_run_is_found_in_the_graph_the_next_run_loads() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let repo = AnalyticsRepository::new(pool.clone());
    let user = seed_user(&pool, "cfg").await;

    // Raised in the draft, nothing published: the draft is what runs.
    let raised = seed_hot_node(&pool, user, "raised").await;
    set_draft(&pool, raised, &graph_with_limit("compose", 20_000_000)).await;
    // Raised in the draft, but the published version still says 10 M.
    let unpublished = seed_hot_node(&pool, user, "unpublished").await;
    set_draft(&pool, unpublished, &graph_with_limit("compose", 20_000_000)).await;
    publish(
        &pool,
        user,
        unpublished,
        &graph_with_limit("compose", 10_000_000),
    )
    .await;
    // Raised and published.
    let published = seed_hot_node(&pool, user, "published").await;
    set_draft(&pool, published, &graph_with_limit("compose", 24_000_000)).await;
    publish(
        &pool,
        user,
        published,
        &graph_with_limit("compose", 16_000_000),
    )
    .await;
    // The draft is not JSON; the node has no limit of its own.
    let broken = seed_hot_node(&pool, user, "broken").await;
    set_draft(&pool, broken, "{not json").await;
    let bare = seed_hot_node(&pool, user, "bare").await;
    // Well below the threshold, with a limit in its graph: never looked up.
    let cool = seed_workflow(&pool, user, "cool").await;
    let exec = seed_execution(&pool, cool, user, false).await;
    seed_rollup(
        &pool,
        Some(cool),
        exec,
        "compose",
        1_000_000,
        10_000_000,
        5,
        "completed",
    )
    .await;
    set_draft(&pool, cool, &graph_with_limit("compose", 20_000_000)).await;

    let mut rows = repo
        .get_node_fuel_headroom(Some(user), 30, 100)
        .await
        .expect("headroom read");
    assert!(rows.iter().all(|r| r.configured_max_fuel.is_none()));
    repo.attach_configured_limits(&mut rows, 0.80, Some(user))
        .await
        .expect("configured limits read");

    let of = |wf| row_for(&rows, wf);
    assert_eq!(of(raised).configured_max_fuel, Some(20_000_000));
    assert!(of(raised).utilisation() < 0.80 && of(raised).enforced_utilisation() >= 0.80);
    assert_eq!(
        of(unpublished).configured_max_fuel,
        Some(10_000_000),
        "the published graph is what a triggered run loads"
    );
    assert!(of(unpublished).utilisation() >= 0.80);
    assert_eq!(of(published).configured_max_fuel, Some(16_000_000));
    assert!(of(published).utilisation() < 0.80);
    for unknown in [broken, bare] {
        assert_eq!(of(unknown).configured_max_fuel, None);
        assert!(of(unknown).utilisation() >= 0.80, "unknown stays reported");
    }
    assert_eq!(
        of(cool).configured_max_fuel,
        None,
        "a node below the threshold is not looked up"
    );
}

/// The lookup is scoped to the caller's workflows, as the headroom read is.
/// Rows naming another owner's workflow get nothing from it.
#[tokio::test]
async fn configured_limits_are_read_for_the_callers_workflows_only() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let repo = AnalyticsRepository::new(pool.clone());
    let owner = seed_user(&pool, "cfg-owner").await;
    let other = seed_user(&pool, "cfg-other").await;
    let wf = seed_hot_node(&pool, owner, "owned").await;
    set_draft(&pool, wf, &graph_with_limit("compose", 20_000_000)).await;

    let fresh = || async {
        repo.get_node_fuel_headroom(Some(owner), 30, 100)
            .await
            .expect("headroom read")
    };

    // The owner's rows, handed to a lookup scoped to someone else.
    let mut rows = fresh().await;
    repo.attach_configured_limits(&mut rows, 0.80, Some(other))
        .await
        .expect("configured limits read");
    assert_eq!(
        row_for(&rows, wf).configured_max_fuel,
        None,
        "another owner's scope must not read this workflow's graph"
    );

    // Control: the owner's scope, and the fleet-wide sweep, both read it.
    for scope in [Some(owner), None] {
        let mut rows = fresh().await;
        repo.attach_configured_limits(&mut rows, 0.80, scope)
            .await
            .expect("configured limits read");
        assert_eq!(
            row_for(&rows, wf).configured_max_fuel,
            Some(20_000_000),
            "{scope:?}"
        );
    }
}
