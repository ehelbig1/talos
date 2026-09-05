//! A workflow the hourly recompute scored an hour ago is not "unscored".
//!
//! `workflows` carries TWO timestamp columns for one fact and two writers that
//! each stamp only their own:
//!
//! * `controller/src/bootstrap/background.rs` (hourly, every workflow) —
//!   `readiness_computed_at`
//! * `AnalyticsRepository::set_workflow_readiness_score`, the on-demand
//!   `get_readiness_breakdown` tool — `readiness_scored_at`
//!
//! Every reader anchored on the second. Measured on the dev fleet 2026-09-05:
//! `readiness_computed_at` set on 36 of 36 rows (max 15:34 that afternoon),
//! `readiness_scored_at` set on **1** — and `get_all_readiness_scores` answered
//! `unscored_count: 27` of 28 beside per-row scores of 87.
//!
//! Each test drives the WRITER'S REAL STATEMENT — the background one is copied
//! verbatim from `background.rs`, not paraphrased, for the reason
//! `updated_at_maintenance_tests` records: a synthetic statement can be green
//! over the shape the writer actually issues.
//!
//! Every assertion comes in a pair. A test that only proves "the background
//! row is not unscored" would pass on a tree where the predicate had been
//! deleted entirely, so each is matched by a positive control proving the
//! predicate still says "unscored" when it should.
//!
//! These are DB tests on the `common` harness (each gets a template clone of
//! the migrated DB), so they belong in CTRL_TESTS, not TC_TESTS.

mod common;

use sqlx::{Pool, Postgres};
use talos_analytics_repository::{AnalyticsRepository, ReadinessScorer};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'readiness test')",
    )
    .bind(id)
    .bind(format!("readiness-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, $3, '{\"nodes\":[],\"edges\":[]}', 'talos://t', 'published')",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// VERBATIM from `controller/src/bootstrap/background.rs`'s readiness
/// recomputation loop. Copied rather than paraphrased on purpose: this exact
/// statement is the one that leaves `readiness_scored_at` NULL.
async fn background_recompute(pool: &Pool<Postgres>, wf: Uuid, score: i32) {
    sqlx::query(
        "UPDATE workflows SET readiness_score = $1, readiness_computed_at = NOW() WHERE id = $2",
    )
    .bind(score)
    .bind(wf)
    .execute(pool)
    .await
    .expect("background readiness recompute");
}

async fn state_of(
    repo: &AnalyticsRepository,
    user: Uuid,
    wf: Uuid,
) -> talos_analytics_repository::ReadinessState {
    let rows = repo
        .list_readiness_scores(user, Some(&[wf]), None, false)
        .await
        .expect("list_readiness_scores");
    let row = rows
        .iter()
        .find(|r| r.id == wf)
        .expect("the seeded workflow is in its own filtered listing");
    talos_analytics_repository::classify_readiness_state(
        row.readiness_score,
        row.readiness_scored_at,
        row.readiness_computed_at,
    )
}

// ───────────────────── F1: the reported defect ─────────────────────

/// F1 REPRODUCTION. Pre-fix this FAILS twice over: `summary.unscored_count`
/// reports 1 (the number an operator reads), and the per-row label reads
/// "unscored" beside a score of 87.
#[tokio::test]
async fn a_background_scored_workflow_is_not_unscored() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user, "background-scored").await;
    let repo = AnalyticsRepository::new(pool.clone());

    background_recompute(&pool, wf, 87).await;

    // The row really carries the shape this is about: score written, the
    // BREAKDOWN's column still NULL. Without this the test could pass because
    // the UPDATE silently matched nothing.
    let rows = repo
        .list_readiness_scores(user, Some(&[wf]), None, false)
        .await
        .expect("list_readiness_scores");
    let row = &rows[0];
    assert_eq!(row.readiness_score, Some(87));
    assert!(
        row.readiness_scored_at.is_none(),
        "the background writer must not have stamped the breakdown's column — \
         if it now does, this test is no longer exercising the reported shape"
    );
    assert!(row.readiness_computed_at.is_some());

    let state = state_of(&repo, user, wf).await;
    assert!(
        !state.is_unscored,
        "a workflow the hourly recompute scored is scored"
    );
    assert_eq!(state.label, "scored");
    assert_eq!(
        state.scored_by,
        Some(ReadinessScorer::BackgroundRecompute),
        "the report must name WHICH scorer produced the number — the two do not \
         compute the same reliability component"
    );
    assert_eq!(
        state.scored_at, row.readiness_computed_at,
        "score_age_hours is derived from this, and it must date the number \
         actually sitting in readiness_score"
    );

    let population = repo
        .readiness_population(user, Some(&[wf]), None, false)
        .await
        .expect("readiness_population");
    assert_eq!(
        population.unscored, 0,
        "summary.unscored_count is the figure an operator acts on; it must use \
         the same predicate as the per-row label"
    );
    assert_eq!(population.total, 1);
}

// ───────────────────── positive controls ─────────────────────

/// The control the negative assertion above cannot supply on its own: with
/// both columns NULL the answer is STILL "unscored", and the summary still
/// counts it. Deleting the predicate would pass the F1 test and fail this one.
#[tokio::test]
async fn a_never_scored_workflow_is_still_unscored() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user, "never-scored").await;
    let repo = AnalyticsRepository::new(pool.clone());

    let state = state_of(&repo, user, wf).await;
    assert!(state.is_unscored);
    assert_eq!(state.label, "unscored");
    assert_eq!(state.scored_at, None);
    assert_eq!(state.scored_by, None);

    let population = repo
        .readiness_population(user, Some(&[wf]), None, false)
        .await
        .expect("readiness_population");
    assert_eq!(population.unscored, 1);
}

/// The other control: a workflow the FULL breakdown scored is still "scored",
/// and still attributed to the breakdown. Widening the input set must not
/// relabel the one row shape that was already classified correctly.
#[tokio::test]
async fn a_breakdown_scored_workflow_is_still_scored() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user, "breakdown-scored").await;
    let repo = AnalyticsRepository::new(pool.clone());

    // The on-demand writer's real method, not a hand-written UPDATE.
    let affected = repo
        .set_workflow_readiness_score(wf, user, 64)
        .await
        .expect("set_workflow_readiness_score");
    assert_eq!(affected, 1, "the write-back must have matched the row");

    let state = state_of(&repo, user, wf).await;
    assert!(!state.is_unscored);
    assert_eq!(state.label, "scored");
    assert_eq!(state.scored_by, Some(ReadinessScorer::Breakdown));

    let population = repo
        .readiness_population(user, Some(&[wf]), None, false)
        .await
        .expect("readiness_population");
    assert_eq!(population.unscored, 0);
}

/// `pa-chief-of-staff`'s live shape: breakdown-scored in July, recomputed by
/// the background job today. It reported `score_age_hours: 986` — dating a
/// score from that afternoon to six weeks earlier. The effective timestamp is
/// the more recent of the two, and it names the scorer that produced it.
#[tokio::test]
async fn the_reported_age_dates_the_score_that_is_actually_stored() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user, "both-columns").await;
    let repo = AnalyticsRepository::new(pool.clone());

    repo.set_workflow_readiness_score(wf, user, 40)
        .await
        .expect("breakdown write-back");
    // Age the breakdown stamp so "more recent" is unambiguous.
    sqlx::query(
        "UPDATE workflows SET readiness_scored_at = NOW() - INTERVAL '41 days' WHERE id = $1",
    )
    .bind(wf)
    .execute(&pool)
    .await
    .expect("age the breakdown stamp");
    background_recompute(&pool, wf, 87).await;

    let state = state_of(&repo, user, wf).await;
    assert_eq!(state.scored_by, Some(ReadinessScorer::BackgroundRecompute));
    let age_hours = (chrono::Utc::now() - state.scored_at.expect("scored")).num_hours();
    assert!(
        age_hours < 1,
        "the score stored on the row was written seconds ago; reported age was \
         {age_hours}h, which is the July timestamp"
    );
}

/// The two consumers must agree at the DATABASE level, not only in the pure
/// classifier: `readiness_population`'s SQL predicate and
/// `classify_readiness_state` are written in different languages in different
/// files, and a divergence there is exactly the defect MCP-1211 fixed once.
#[tokio::test]
async fn the_population_count_and_the_row_labels_agree() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let never = seed_workflow(&pool, user, "z-never").await;
    let background = seed_workflow(&pool, user, "z-background").await;
    let breakdown = seed_workflow(&pool, user, "z-breakdown").await;
    background_recompute(&pool, background, 30).await;
    repo.set_workflow_readiness_score(breakdown, user, 55)
        .await
        .expect("breakdown write-back");

    let ids = [never, background, breakdown];
    let rows = repo
        .list_readiness_scores(user, Some(&ids), None, false)
        .await
        .expect("list_readiness_scores");
    assert_eq!(rows.len(), 3);
    let labelled_unscored = rows
        .iter()
        .filter(|r| {
            talos_analytics_repository::classify_readiness_state(
                r.readiness_score,
                r.readiness_scored_at,
                r.readiness_computed_at,
            )
            .is_unscored
        })
        .count() as i64;

    let population = repo
        .readiness_population(user, Some(&ids), None, false)
        .await
        .expect("readiness_population");
    assert_eq!(
        population.unscored, labelled_unscored,
        "the summary counter and the per-row labels disagreed"
    );
    assert_eq!(population.unscored, 1, "only the never-scored one");
}
