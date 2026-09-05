//! A workflow that runs every day as somebody's sub-workflow is not dormant.
//!
//! `execute_subworkflow_graph` runs a child IN-PROCESS and records no
//! `workflow_executions` row — measured 2026-09-05: ZERO rows carrying
//! `parent_execution_id` across the live table and the archive, platform-wide.
//! `get_platform_hygiene_report`'s dormant query read that table alone, so the
//! flagship `pa-chief-of-staff`'s own `cos-team-recall` (its daily `team_gather`
//! sub-workflow) and `pa-quality-judge` (the judge of three workflows) were both
//! listed with `last_execution: null` under a recommendation to *"Consider
//! disabling or deleting them with `batch_delete_workflows`"*. Following it
//! would have removed the flagship's team dimension.
//!
//! Every test comes in a pair. The exclusion is only correct if a GENUINELY
//! dormant workflow is still listed AND still counted — a test that only
//! proves "the child is excluded" would pass on a tree where the whole
//! recommendation had been deleted.
//!
//! These are DB tests on the `common` harness (each gets a template clone of
//! the migrated DB), so they belong in CTRL_TESTS, not TC_TESTS.

mod common;

use sqlx::{Pool, Postgres};
use talos_analytics_repository::AnalyticsRepository;
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'dormant test')",
    )
    .bind(id)
    .bind(format!("dormant-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// Seeded 60 days old so it clears the dormant query's
/// `created_at < NOW() - INTERVAL '30 days'` gate.
async fn seed_workflow(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    graph: &str,
    enabled: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled, created_at) \
         VALUES ($1, $2, $3, $4, 'talos://t', 'published', $5, NOW() - INTERVAL '60 days')",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(graph)
    .bind(enabled)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// `workflow_executions.actor_id` is NOT NULL, so a live-execution fixture
/// needs an actor of its own.
async fn seed_actor(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'dormant-test-actor')")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

const EMPTY_GRAPH: &str = r#"{"nodes":[],"edges":[]}"#;

fn sub_workflow_graph(child: Uuid) -> String {
    format!(
        r#"{{"nodes":[{{"id":"gather","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
    )
}

async fn dormant_names(repo: &AnalyticsRepository, user: Uuid) -> Vec<String> {
    repo.get_hygiene_report(user)
        .await
        .expect("hygiene report")
        .dormant_workflows
        .iter()
        .map(|r| r.name.clone())
        .collect()
}

/// The dormant cleanup recommendation, as an operator sees it.
fn dormant_recommendation(
    report: &talos_analytics_repository::HygieneReport,
) -> Option<serde_json::Value> {
    let outcome = talos_hygiene_service::build_report(report);
    outcome
        .report
        .get("recommendations")?
        .as_array()?
        .iter()
        .find(|r| {
            r.get("action")
                .and_then(|a| a.as_str())
                .is_some_and(|a| a.contains("no executions in 30+ days"))
        })
        .cloned()
}

// ───────────────────── F2: the reported defect ─────────────────────

/// F2 REPRODUCTION. Pre-fix this FAILS on `affected_count`: the child is
/// counted in a recommendation whose action names `batch_delete_workflows`.
#[tokio::test]
async fn a_sub_workflow_of_an_enabled_parent_is_not_recommended_for_deletion() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let child = seed_workflow(&pool, user, "cos-team-recall", EMPTY_GRAPH, true).await;
    seed_workflow(
        &pool,
        user,
        "pa-chief-of-staff",
        &sub_workflow_graph(child),
        true,
    )
    .await;

    let report = repo.get_hygiene_report(user).await.expect("hygiene report");

    // The child IS still listed — an operator asking "what has no executions?"
    // should see it, with the reason.
    let row = report
        .dormant_workflows
        .iter()
        .find(|r| r.id == child)
        .expect("the child is still listed among workflows with no executions");
    assert_eq!(
        row.runs_as_child_of,
        vec!["pa-chief-of-staff".to_string()],
        "the child must name the enabled parent that dispatches into it"
    );
    assert!(
        row.last_execution.is_none(),
        "the premise of the whole test: a sub-workflow leaves no execution row"
    );

    // …and it is NOT in the population the delete advice speaks about.
    let rec = dormant_recommendation(&report);
    match rec {
        None => { /* the parent ran nothing either, so no advice at all — fine */ }
        Some(rec) => {
            let deletable: Vec<String> = rec["deletable"]
                .as_array()
                .expect("deletable list")
                .iter()
                .map(|v| v.as_str().unwrap_or_default().to_string())
                .collect();
            assert!(
                !deletable.contains(&"cos-team-recall".to_string()),
                "the flagship's daily sub-workflow was recommended for deletion: {deletable:?}"
            );
            assert_eq!(
                rec["excluded_child_workflows"].as_i64(),
                Some(1),
                "the exclusion must be DISCLOSED — a count that silently disagrees with the \
                 list above it is its own misleading report"
            );
        }
    }
}

/// The control the exclusion cannot supply on its own: a top-level workflow
/// nobody dispatches into is STILL listed and STILL counted. Deleting the
/// recommendation entirely would pass the test above and fail this one.
#[tokio::test]
async fn a_genuinely_dormant_top_level_workflow_is_still_listed_and_counted() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    seed_workflow(&pool, user, "abandoned-experiment", EMPTY_GRAPH, true).await;

    let report = repo.get_hygiene_report(user).await.expect("hygiene report");
    let row = report
        .dormant_workflows
        .iter()
        .find(|r| r.name == "abandoned-experiment")
        .expect("listed");
    assert!(
        row.runs_as_child_of.is_empty(),
        "nothing dispatches into it"
    );

    let rec = dormant_recommendation(&report).expect("the cleanup advice must still fire");
    assert_eq!(rec["affected_count"].as_i64(), Some(1));
    assert_eq!(rec["excluded_child_workflows"].as_i64(), Some(0));
    assert!(
        !rec["action"]
            .as_str()
            .unwrap_or_default()
            .contains("EXCLUDED"),
        "with nothing excluded the advice must not claim an exclusion"
    );
}

/// The child keys a `sub_workflow_id`-only scan misses. `judge_workflow_id`
/// is the one `pa-quality-judge` is reached through on the live fleet, and
/// `llm_dispatch`'s `routes` is the one no key-NAME convention can see —
/// its targets are the VALUES of an arbitrarily-labelled object.
#[tokio::test]
async fn a_judge_and_an_llm_dispatch_route_target_are_children_too() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let judge = seed_workflow(&pool, user, "pa-quality-judge", EMPTY_GRAPH, true).await;
    let routed = seed_workflow(&pool, user, "billing-handler", EMPTY_GRAPH, true).await;
    let classifier = seed_workflow(&pool, user, "intent-classifier", EMPTY_GRAPH, true).await;
    let graph = format!(
        r#"{{"nodes":[
             {{"id":"j","type":"system:judge","data":{{"judge_workflow_id":"{judge}"}}}},
             {{"id":"d","type":"system:llm_dispatch","data":{{
                "classifier_workflow_id":"{classifier}",
                "routes":{{"billing":"{routed}"}}}}}}
           ],"edges":[]}}"#
    );
    seed_workflow(&pool, user, "pa-daily-brief", &graph, true).await;

    let report = repo.get_hygiene_report(user).await.expect("hygiene report");
    for (id, label) in [
        (judge, "judge_workflow_id"),
        (routed, "routes.<label>"),
        (classifier, "classifier_workflow_id"),
    ] {
        let row = report
            .dormant_workflows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{label} target should be listed"));
        assert_eq!(
            row.runs_as_child_of,
            vec!["pa-daily-brief".to_string()],
            "{label} must be recognised as a child reference"
        );
    }

    let rec = dormant_recommendation(&report);
    if let Some(rec) = rec {
        let deletable: Vec<String> = rec["deletable"]
            .as_array()
            .expect("deletable")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        // The PARENT is legitimately deletable — nothing dispatches into it and
        // it has never run. Only the three children must be spared.
        for child in ["pa-quality-judge", "billing-handler", "intent-classifier"] {
            assert!(
                !deletable.contains(&child.to_string()),
                "{child} is a child and must not be recommended for deletion: {deletable:?}"
            );
        }
        assert_eq!(
            rec["excluded_child_workflows"].as_i64(),
            Some(3),
            "all three child references must be recognised and disclosed"
        );
    }
}

/// The exclusion is keyed on an ENABLED parent. A child whose only parent is
/// disabled genuinely IS abandoned, and the advice must still reach it —
/// otherwise "referenced anywhere, ever" becomes a permanent immunity.
#[tokio::test]
async fn a_child_of_a_disabled_parent_is_not_protected() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let child = seed_workflow(&pool, user, "orphaned-child", EMPTY_GRAPH, true).await;
    seed_workflow(
        &pool,
        user,
        "retired-parent",
        &sub_workflow_graph(child),
        false, // disabled
    )
    .await;

    let report = repo.get_hygiene_report(user).await.expect("hygiene report");
    let row = report
        .dormant_workflows
        .iter()
        .find(|r| r.id == child)
        .expect("listed");
    assert!(
        row.runs_as_child_of.is_empty(),
        "a disabled parent dispatches into nothing"
    );

    let rec = dormant_recommendation(&report).expect("advice fires");
    let deletable: Vec<String> = rec["deletable"]
        .as_array()
        .expect("deletable")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(deletable.contains(&"orphaned-child".to_string()));
}

/// A workflow that dispatches into ITSELF must not become permanently immune
/// to the advice: the exclusion exists because a DIFFERENT workflow's runs
/// hide this one's, and a self-reference hides nothing.
#[tokio::test]
async fn a_self_referencing_workflow_does_not_protect_itself() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled, created_at) \
         VALUES ($1, $2, 'recursive', $3, 'talos://t', 'published', true, NOW() - INTERVAL '60 days')",
    )
    .bind(id)
    .bind(user)
    .bind(sub_workflow_graph(id))
    .execute(&pool)
    .await
    .expect("seed self-referencing workflow");

    let report = repo.get_hygiene_report(user).await.expect("hygiene report");
    let row = report
        .dormant_workflows
        .iter()
        .find(|r| r.id == id)
        .expect("listed");
    assert!(row.runs_as_child_of.is_empty());
}

/// The dormant query's 30-day window and the archive sweep's default
/// `ARCHIVE_AFTER_DAYS` are both 30, so on a default deployment a live-table
/// read happens to give the right answer. That coincidence is not the
/// contract: at `ARCHIVE_AFTER_DAYS=7` a workflow that ran 8 days ago has had
/// its row MOVED, and a live-only `MAX(started_at)` reads it as never-run.
#[tokio::test]
async fn a_run_that_lives_only_in_the_archive_still_counts() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let wf = seed_workflow(&pool, user, "recently-archived", EMPTY_GRAPH, true).await;
    sqlx::query(
        "INSERT INTO workflow_executions_archive \
             (id, workflow_id, user_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, 'completed', NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days')",
    )
    .bind(Uuid::new_v4())
    .bind(wf)
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed archived execution");

    let names = dormant_names(&repo, user).await;
    assert!(
        !names.contains(&"recently-archived".to_string()),
        "a workflow that ran 8 days ago is not dormant just because retention \
         moved its row: {names:?}"
    );

    // Control: the same shape at 40 days old IS dormant, so this is not
    // passing because the archive read swallows every row.
    let old = seed_workflow(&pool, user, "long-archived", EMPTY_GRAPH, true).await;
    sqlx::query(
        "INSERT INTO workflow_executions_archive \
             (id, workflow_id, user_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, 'completed', NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days')",
    )
    .bind(Uuid::new_v4())
    .bind(old)
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed old archived execution");

    let names = dormant_names(&repo, user).await;
    assert!(
        names.contains(&"long-archived".to_string()),
        "a workflow whose last run was 40 days ago is dormant: {names:?}"
    );
}

/// A live execution inside the window still suppresses the row — the archive
/// read is additive, not a replacement.
#[tokio::test]
async fn a_recent_live_execution_still_suppresses_the_row() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let actor = seed_actor(&pool, user).await;
    let wf = seed_workflow(&pool, user, "busy-workflow", EMPTY_GRAPH, true).await;
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
    .expect("seed live execution");

    let names = dormant_names(&repo, user).await;
    assert!(!names.contains(&"busy-workflow".to_string()), "{names:?}");
}
