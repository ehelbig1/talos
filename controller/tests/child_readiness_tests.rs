//! A child's reliability and freshness are UNMEASURABLE, not zero.
//!
//! `execute_subworkflow_graph` runs a child IN-PROCESS and records no
//! `workflow_executions` row — measured 2026-09-05: ZERO rows carrying
//! `parent_execution_id` across the live table AND the archive, platform-wide,
//! over 10 140 rows. Reliability (50 pts) and freshness (20 pts) are read from
//! that table and from nothing else, so THREE independent scorers — the
//! on-demand `get_readiness_breakdown`, `validate_workflow`, and the hourly
//! recompute in `controller/src/bootstrap/background.rs` — each gave every
//! parent-dispatched workflow 0 for both, out of 100.
//!
//! Live on the reference deployment when this was written, and it is the whole
//! fleet's population of children, not a sample:
//!
//! ```text
//! cos-team-recall  19   parent pa-chief-of-staff  (the flagship's daily team gather)
//! pa-ask           19   parent pa-ask-email       (runs per inbound email)
//! pa-quality-judge 19   parents pa-chief-of-staff, pa-daily-brief, pa-meeting-prep
//! stress-05-child  14   parent stress-05-parent
//! ```
//!
//! …against a fleet otherwise sitting at 40–87, with the hourly loop PERSISTING
//! those numbers to `workflows.readiness_score` and `get_all_readiness_scores`
//! reading them back and sorting ascending. The flagship's own daily
//! sub-workflow read as the least production-ready workflow on the platform.
//!
//! # What these tests drive, and what they cannot
//!
//! They drive the REAL scan query (`AnalyticsRepository::scan_child_parents_for`
//! → `talos_child_workflow_refs::scan_child_parents`), the REAL shared scorer
//! (`score_readiness` — the one function all three scorers now call, so
//! removing the classification from it turns every basis test here red), and
//! the background writer's VERBATIM `UPDATE` statement, copied rather than
//! paraphrased for the reason `updated_at_maintenance_tests` records: a
//! synthetic statement can be green over the shape the writer actually issues.
//!
//! **Stated limit.** `controller/src/bootstrap/background.rs` is `mod
//! bootstrap` inside `main.rs`, i.e. bin-private, so no integration test can
//! call its loop. Deleting the loop's `child_scans` lookup would leave every
//! test here green. What IS covered by construction is the shared decision:
//! the loop, the breakdown and `validate_workflow` all call `score_readiness`
//! and `ReadinessBasis::from_scan`, so the three cannot disagree about the
//! scale even though they still deliberately disagree about the reliability
//! INPUT (the breakdown excludes acknowledged failures; the loop counts them —
//! #758 chose to disclose that rather than unify it).
//!
//! Every assertion comes in a pair. A test proving only "the child is scored on
//! 30" would pass on a tree where the full scale had been deleted, so each is
//! matched by a control proving a TOP-LEVEL workflow with no runs is STILL
//! scored 0 reliability out of 100 — because for it the silence really does
//! mean it never ran.
//!
//! These are DB tests on the `common` harness (each gets a template clone of
//! the migrated DB), so they belong in CTRL_TESTS, not TC_TESTS.

mod common;

use sqlx::{Pool, Postgres, Row};
use talos_analytics_repository::{
    score_readiness, AnalyticsRepository, ReadinessBasis, ReadinessComponents,
    CHILD_MEASURABLE_MAX, FULL_MAX,
};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'child readiness')",
    )
    .bind(id)
    .bind(format!("child-readiness-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    graph: &str,
    enabled: bool,
    status: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, $4, 'talos://t', $5, $6)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(graph)
    .bind(status)
    .bind(enabled)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_actor(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'child-readiness-actor')")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

const EMPTY_GRAPH: &str = r#"{"nodes":[],"edges":[]}"#;

/// The shape the ENGINE writes: `type` on the node, the child id under `data`.
/// Six nodes of this shape were on the reference fleet 2026-09-05.
fn sub_workflow_graph(child: Uuid) -> String {
    format!(
        r#"{{"nodes":[{{"id":"gather","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
    )
}

/// VERBATIM from `controller/src/bootstrap/background.rs`'s readiness
/// recomputation loop. Copied rather than paraphrased on purpose: this exact
/// statement is what persists the number `get_all_readiness_scores` reads back.
async fn background_persist(pool: &Pool<Postgres>, wf: Uuid, score: i32) {
    sqlx::query(
        "UPDATE workflows SET readiness_score = $1, readiness_computed_at = NOW() WHERE id = $2",
    )
    .bind(score)
    .bind(wf)
    .execute(pool)
    .await
    .expect("background readiness persist");
}

/// A workflow that is documented and low-risk but has NEVER been observed
/// executing — which is the exact state every child on the fleet is in.
fn documented_but_unobserved() -> ReadinessComponents {
    ReadinessComponents {
        reliability: 0.0,
        documentation: 20.0,
        freshness: 0.0,
        risk: 10.0,
    }
}

// ───────────────────── F1: the reported defect ─────────────────────

/// F1 REPRODUCTION. Pre-fix this fails on BOTH assertions: the score is 30 out
/// of a hardcoded 100 (so `below_50_count` counts it and the ascending page
/// puts it first), and there is no denominator in the answer to say otherwise.
#[tokio::test]
async fn a_parent_dispatched_workflow_is_scored_on_the_measurable_components_only() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let child = seed_workflow(&pool, user, "cos-team-recall", EMPTY_GRAPH, true, "draft").await;
    seed_workflow(
        &pool,
        user,
        "pa-chief-of-staff",
        &sub_workflow_graph(child),
        true,
        "published",
    )
    .await;

    // The REAL scan query — LIKE prefilter, enabled + non-archived predicate,
    // graph parsed through the engine's own key set.
    let scan = repo
        .scan_child_parents_for(user, &[child])
        .await
        .expect("child scan");
    assert_eq!(
        scan.parents_of(child),
        ["pa-chief-of-staff".to_string()],
        "the scan must see the parent through the shape the engine writes"
    );

    let outcome = score_readiness(
        documented_but_unobserved(),
        ReadinessBasis::from_scan(&scan, child),
    );
    assert_eq!(
        outcome.max_points, CHILD_MEASURABLE_MAX,
        "the DENOMINATOR shrinks — this is the field that says the two numbers \
         are not on one scale"
    );
    assert_eq!(outcome.score, 30, "documentation 20 + risk 10, out of 30");
    assert!(!outcome.comparable_to_fleet());
    assert_eq!(outcome.unmeasured, ["reliability", "freshness"]);
    assert!(
        outcome.note().unwrap().contains("pa-chief-of-staff"),
        "the operator must be told WHO dispatches it, not merely that somebody does"
    );

    // …and the number the background writer's own statement persists is that
    // one, read back through the reader `get_all_readiness_scores` uses.
    background_persist(&pool, child, outcome.score).await;
    let rows = repo
        .list_readiness_scores(user, Some(&[child]), None, false)
        .await
        .expect("list_readiness_scores");
    assert_eq!(rows[0].readiness_score, Some(30));
}

/// The POSITIVE CONTROL, and it is the assertion that makes the one above mean
/// anything: a top-level workflow with zero runs is STILL scored 0 reliability
/// out of 100. For it the silence in `workflow_executions` genuinely means it
/// never ran, and softening that would be the same defect pointed the other way.
#[tokio::test]
async fn a_top_level_workflow_with_no_runs_is_still_scored_zero_reliability_out_of_a_hundred() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let orphan = seed_workflow(
        &pool,
        user,
        "nobody-runs-me",
        EMPTY_GRAPH,
        true,
        "published",
    )
    .await;

    let scan = repo
        .scan_child_parents_for(user, &[orphan])
        .await
        .expect("child scan");
    let basis = ReadinessBasis::from_scan(&scan, orphan);
    assert_eq!(basis, ReadinessBasis::FullScale);

    let outcome = score_readiness(documented_but_unobserved(), basis);
    assert_eq!(outcome.max_points, FULL_MAX);
    assert_eq!(outcome.score, 30, "30 of 100 — genuinely unready");
    assert!(outcome.comparable_to_fleet());
    assert!(outcome.unmeasured.is_empty());
    assert_eq!(outcome.note(), None, "nothing to say ⇒ no note");
}

/// The scan's own predicate, which decides which parents count. An ARCHIVED or
/// DISABLED parent does not protect a child from being scored as unrun — a
/// deliberate choice (a retired parent dispatches nothing), pinned so it is a
/// visible decision rather than an accident of the WHERE clause.
#[tokio::test]
async fn a_retired_parent_does_not_make_a_workflow_a_child() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let child = seed_workflow(&pool, user, "orphaned-child", EMPTY_GRAPH, true, "draft").await;
    seed_workflow(
        &pool,
        user,
        "archived-parent",
        &sub_workflow_graph(child),
        true,
        "archived",
    )
    .await;
    seed_workflow(
        &pool,
        user,
        "disabled-parent",
        &sub_workflow_graph(child),
        false,
        "published",
    )
    .await;

    let scan = repo
        .scan_child_parents_for(user, &[child])
        .await
        .expect("child scan");
    assert!(scan.parents_of(child).is_empty());
    assert_eq!(
        ReadinessBasis::from_scan(&scan, child),
        ReadinessBasis::FullScale
    );
}

/// Tenancy: another user's parent naming this id must not change how this
/// user's workflow is scored. The scan binds `user_id`; this proves it.
#[tokio::test]
async fn another_users_parent_does_not_reach_across_the_tenancy_boundary() {
    let (pool, _db) = common::isolated_db_pool().await;
    let mine = seed_user(&pool).await;
    let theirs = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let child = seed_workflow(&pool, mine, "my-workflow", EMPTY_GRAPH, true, "published").await;
    seed_workflow(
        &pool,
        theirs,
        "their-parent",
        &sub_workflow_graph(child),
        true,
        "published",
    )
    .await;

    let scan = repo
        .scan_child_parents_for(mine, &[child])
        .await
        .expect("child scan");
    assert!(
        scan.parents_of(child).is_empty(),
        "a parent belonging to a different tenant must be invisible here"
    );
}

// ───────────────────── F2: the reuse report ─────────────────────

/// F2 REPRODUCTION. `get_workflow_reuse_stats` INNER-JOINs
/// `workflow_executions`, so a workflow whose every invocation is a parent
/// dispatch is ABSENT from the reuse tool — not reported as zero, absent.
/// Measured live: `pa-ask` runs per inbound email and has 0 rows in that table
/// across live and archive, and it was the most-invoked workflow on the fleet.
#[tokio::test]
async fn a_parent_dispatched_workflow_is_absent_from_the_counted_reuse_list() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let child = seed_workflow(&pool, user, "pa-ask", EMPTY_GRAPH, true, "published").await;
    seed_workflow(
        &pool,
        user,
        "pa-ask-email",
        &sub_workflow_graph(child),
        true,
        "published",
    )
    .await;

    let counted = repo
        .get_workflow_reuse_stats(user, 30)
        .await
        .expect("reuse stats");
    assert!(
        !counted.iter().any(|r| r.workflow_id == child),
        "the counted list structurally cannot contain it — that is the defect, \
         and it is not fixed by folding it in with a count of 0"
    );

    // …and the new candidate page + the ONE scan is what surfaces it, with the
    // count left UNKNOWN rather than asserted as zero.
    let candidates = repo
        .list_zero_invocation_workflows(user, 30, 100)
        .await
        .expect("zero-invocation candidates");
    let ids: Vec<Uuid> = candidates.iter().map(|c| c.workflow_id).collect();
    assert!(ids.contains(&child));

    let scan = repo.scan_child_parents_for(user, &ids).await.expect("scan");
    assert_eq!(scan.parents_of(child), ["pa-ask-email".to_string()]);

    // The CONTROL: a workflow with zero runs and no parent is not reuse, and
    // must not be promoted into the new list just for being unrun.
    let orphan = seed_workflow(&pool, user, "never-run", EMPTY_GRAPH, true, "published").await;
    let candidates = repo
        .list_zero_invocation_workflows(user, 30, 100)
        .await
        .expect("zero-invocation candidates");
    let ids: Vec<Uuid> = candidates.iter().map(|c| c.workflow_id).collect();
    let scan = repo.scan_child_parents_for(user, &ids).await.expect("scan");
    assert!(
        scan.parents_of(orphan).is_empty(),
        "zero runs and nobody dispatching it is not reuse"
    );
}

// ───────────────────── F5: the dead exclusion ─────────────────────

/// The exclusion `get_frequently_executed_unscheduled` carried read
/// `node.module_id = 'system:sub_workflow'` and `node.config.sub_workflow_id`.
/// Measured against the live fleet 2026-09-05 that predicate matched **0**
/// nodes while the engine's shape matched 6 — so a filter added to cut a
/// false-positive rate had never excluded anything.
///
/// This runs BOTH predicates as SQL against a real, engine-shaped row, so the
/// pin is against the database rather than against a recollection of the schema
/// — which is what r242 and r243 each got wrong in turn.
#[tokio::test]
async fn the_retired_exclusion_predicate_matches_nothing_the_engine_writes() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_workflow(&pool, user, "the-child", EMPTY_GRAPH, true, "published").await;
    seed_workflow(
        &pool,
        user,
        "the-parent",
        &sub_workflow_graph(child),
        true,
        "published",
    )
    .await;

    // r243's predicate, verbatim from the retired SQL.
    let dead: i64 = sqlx::query(
        "SELECT COUNT(*)::bigint AS n FROM workflows other \
         WHERE other.user_id = $1 \
           AND jsonb_typeof(other.graph_json::jsonb -> 'nodes') = 'array' \
           AND EXISTS ( \
               SELECT 1 FROM jsonb_array_elements(other.graph_json::jsonb -> 'nodes') node \
               WHERE node ->> 'module_id' = 'system:sub_workflow' \
                 AND node #>> '{config,sub_workflow_id}' = $2::text \
           )",
    )
    .bind(user)
    .bind(child)
    .fetch_one(&pool)
    .await
    .expect("dead predicate")
    .try_get::<i64, _>("n")
    .expect("count");
    assert_eq!(
        dead, 0,
        "the retired predicate reads `module_id` and `config`; the engine writes \
         `type` and `data`, so it matched nothing for two years while looking fine"
    );

    // The replacement — the ONE scan — sees it.
    let repo = AnalyticsRepository::new(pool.clone());
    let scan = repo
        .scan_child_parents_for(user, &[child])
        .await
        .expect("scan");
    assert_eq!(scan.parents_of(child), ["the-parent".to_string()]);
}

/// The exclusion is now LIVE, and this is the shape it bites: a HYBRID —
/// dispatched as a child AND triggered directly ≥3 times — since
/// `HAVING COUNT(we.id) >= 3` already excludes a pure child. Stated in the
/// method's own doc comment as vacuous on the reference fleet today; the test
/// constructs the case rather than claiming it cannot happen.
#[tokio::test]
async fn a_hybrid_child_is_excluded_from_the_schedule_suggestion() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let advanced = talos_advanced_repository::AdvancedRepository::new(pool.clone());

    let hybrid = seed_workflow(&pool, user, "hybrid", EMPTY_GRAPH, true, "published").await;
    let plain = seed_workflow(&pool, user, "plain-utility", EMPTY_GRAPH, true, "published").await;
    seed_workflow(
        &pool,
        user,
        "the-parent",
        &sub_workflow_graph(hybrid),
        true,
        "published",
    )
    .await;

    let actor = seed_actor(&pool, user).await;
    for wf in [hybrid, plain] {
        for _ in 0..4 {
            sqlx::query(
                "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
                 VALUES ($1, $2, $3, $4, 'completed', NOW() - INTERVAL '2 days')",
            )
            .bind(Uuid::new_v4())
            .bind(wf)
            .bind(user)
            .bind(actor)
            .execute(&pool)
            .await
            .expect("seed execution");
        }
    }

    let rows = advanced
        .get_frequently_executed_unscheduled(user)
        .await
        .expect("frequently executed");
    let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    assert!(
        !names.contains(&"hybrid"),
        "a workflow a parent already dispatches is invoked on purpose, not unscheduled: {names:?}"
    );
    assert!(
        names.contains(&"plain-utility"),
        "…and the CONTROL must still be suggested, or this passes on a tree where \
         the whole signal was deleted: {names:?}"
    );
}
