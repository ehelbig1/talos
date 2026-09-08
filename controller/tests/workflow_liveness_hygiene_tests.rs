//! Two columns claim to say whether a workflow is live, and the hygiene report
//! read the wrong one.
//!
//! `workflows.is_enabled` is the OPERATOR's pause toggle; `workflows.status` is
//! the LIFECYCLE. The six `UPDATE workflows SET status = 'archived'` sites never
//! clear `is_enabled`, so — measured on the reference fleet 2026-09-07 — every
//! one of the 8 archived rows still reads `is_enabled = true`. The dormant query
//! predicated `w.is_enabled = true` with no status clause, so all 8 were listed
//! under *"Consider disabling or deleting them with `batch_delete_workflows`"*:
//! of the ten workflows that recommendation named, EIGHT had already been retired
//! by the operator it was advising.
//!
//! Every test comes in a PAIR. Excluding archived rows is only correct if a
//! genuinely dormant, genuinely live workflow is still listed and still counted —
//! a test that only proves "the archived one is gone" would pass on a tree where
//! the whole recommendation had been deleted.
//!
//! EXCLUDED is not DROPPED: the count and the names are disclosed under
//! `summary.archived_excluded`, and `null` there means the read failed, never
//! that the operator has retired nothing.
//!
//! These are DB tests on the `common` harness (each gets a template clone of the
//! migrated DB), so they belong in CTRL_TESTS, not TC_TESTS.

mod common;

use sqlx::{Pool, Postgres};
use talos_analytics_repository::AnalyticsRepository;
use uuid::Uuid;

const EMPTY_GRAPH: &str = r#"{"nodes":[],"edges":[]}"#;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'liveness test')",
    )
    .bind(id)
    .bind(format!("liveness-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// Seeded 60 days old so it clears the dormant query's
/// `created_at < NOW() - INTERVAL '30 days'` gate, and with an explicit
/// `status` / `is_enabled` PAIR — the whole point is that the two axes are set
/// independently, exactly as the two production writers set them.
async fn seed_workflow(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    graph: &str,
    status: &str,
    is_enabled: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled, created_at) \
         VALUES ($1, $2, $3, $4, 'talos://t', $5, $6, NOW() - INTERVAL '60 days')",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(graph)
    .bind(status)
    .bind(is_enabled)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

fn sub_workflow_graph(child: Uuid) -> String {
    format!(
        r#"{{"nodes":[{{"id":"gather","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
    )
}

fn dormant_recommendation(
    report: &talos_analytics_repository::HygieneReport,
) -> Option<serde_json::Value> {
    talos_hygiene_service::build_report(
        report,
        &talos_push_channel_inventory::PushChannelReadout::NotConsulted,
    )
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

// ───────────── the defect, and the control that keeps it honest ─────────────

/// THE reproduction. Pre-fix this FAILS: `retired-and-forgotten` is listed
/// beside `still-live-and-dormant` and both are recommended for deletion.
///
/// MUTATION that turns it red again: put `w.is_enabled = true` back in place of
/// `talos_workflow_liveness::dispatchable_sql(Some("w"))`.
#[tokio::test]
async fn an_archived_workflow_is_not_a_dormant_enabled_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    // The fleet's shape: archiving leaves `is_enabled = true` behind.
    seed_workflow(
        &pool,
        user,
        "retired-and-forgotten",
        EMPTY_GRAPH,
        "archived",
        true,
    )
    .await;
    // The CONTROL. Without it, deleting the whole recommendation would pass.
    seed_workflow(
        &pool,
        user,
        "still-live-and-dormant",
        EMPTY_GRAPH,
        "active",
        true,
    )
    .await;

    let report = repo.get_hygiene_report(user).await.expect("hygiene report");
    let names: Vec<&str> = report
        .dormant_workflows
        .iter()
        .map(|r| r.name.as_str())
        .collect();

    assert!(
        !names.contains(&"retired-and-forgotten"),
        "a workflow the operator already archived is not a dormant ENABLED one: {names:?}"
    );
    assert!(
        names.contains(&"still-live-and-dormant"),
        "the control must survive the exclusion, or this test proves nothing: {names:?}"
    );

    let rec = dormant_recommendation(&report).expect("the cleanup advice must still fire");
    assert_eq!(
        rec["affected_count"], 1,
        "the count must equal what the list contains: {rec}"
    );
    assert_eq!(
        rec["deletable"],
        serde_json::json!(["still-live-and-dormant"]),
        "{rec}"
    );
}

/// EXCLUDED is not DROPPED. The retired rows are counted and NAMED, and the
/// recommendation says why its list is shorter than the operator might expect.
///
/// MUTATION: drop the `dormant_archived_fut` read, or render its `None` as 0.
#[tokio::test]
async fn the_archived_exclusion_is_disclosed_with_its_names() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    seed_workflow(&pool, user, "retired-a", EMPTY_GRAPH, "archived", true).await;
    seed_workflow(&pool, user, "retired-b", EMPTY_GRAPH, "archived", true).await;
    seed_workflow(
        &pool,
        user,
        "still-live-and-dormant",
        EMPTY_GRAPH,
        "active",
        true,
    )
    .await;

    let report = repo.get_hygiene_report(user).await.expect("hygiene report");
    let excluded = report
        .dormant_archived_excluded
        .as_ref()
        .expect("the retired half must be measured, not defaulted away");
    assert_eq!(excluded.total, 2);
    assert!(!excluded.truncated);
    let mut names = excluded.names.clone();
    names.sort();
    assert_eq!(names, vec!["retired-a", "retired-b"]);

    let rendered = talos_hygiene_service::build_report(
        &report,
        &talos_push_channel_inventory::PushChannelReadout::NotConsulted,
    )
    .report;
    let block = &rendered["summary"]["archived_excluded"];
    assert_eq!(block["count"], 2, "{block}");
    assert_eq!(block["names_truncated"], false, "{block}");
    assert!(
        block["note"]
            .as_str()
            .unwrap_or_default()
            .contains("is_enabled = true"),
        "the note must name the column that made the pre-fix reading wrong: {block}"
    );

    let rec = dormant_recommendation(&report).expect("advice fires");
    assert_eq!(rec["excluded_archived_workflows"], 2, "{rec}");
    let action = rec["action"].as_str().unwrap_or_default();
    assert!(action.contains("already retired them"), "{action}");
    assert!(action.contains("retired-a"), "{action}");
}

/// A PAUSED workflow is still not dormant-by-neglect — the operator turned it
/// off on purpose — and that behaviour is unchanged by this fix. The pair keeps
/// the two axes from being collapsed into one.
///
/// MUTATION: swap `dispatchable_sql` for `retired_sql`'s negation alone (i.e.
/// drop the `is_enabled` conjunct).
#[tokio::test]
async fn a_paused_workflow_stays_out_and_a_draft_stays_in() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    seed_workflow(
        &pool,
        user,
        "paused-on-purpose",
        EMPTY_GRAPH,
        "active",
        false,
    )
    .await;
    // A DRAFT is not live but IS dispatchable — a draft child is run from its
    // `graph_json` column with no status predicate, and 4 drafts on the
    // reference fleet carry enabled schedules. It stays in the list.
    seed_workflow(
        &pool,
        user,
        "unpublished-but-runnable",
        EMPTY_GRAPH,
        "draft",
        true,
    )
    .await;

    let report = repo.get_hygiene_report(user).await.expect("hygiene report");
    let names: Vec<&str> = report
        .dormant_workflows
        .iter()
        .map(|r| r.name.as_str())
        .collect();
    assert!(!names.contains(&"paused-on-purpose"), "{names:?}");
    assert!(names.contains(&"unpublished-but-runnable"), "{names:?}");
    // A paused workflow is not RETIRED either, so it must not be counted as one.
    assert_eq!(
        report
            .dormant_archived_excluded
            .as_ref()
            .expect("measured")
            .total,
        0,
        "a pause is not an archive"
    );
}

/// The same predicate, read from the same home, at the OTHER two sites that
/// already had it right — so they cannot drift back to their two spellings
/// (`status != 'archived'` and `status <> 'archived'`, in two crates).
///
/// An ARCHIVED parent does not protect a child from deletion: it does not run,
/// so its `sub_workflow` node is not evidence about anything.
#[tokio::test]
async fn an_archived_parent_does_not_protect_its_child() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_workflow(&pool, user, "the-child", EMPTY_GRAPH, "active", true).await;
    seed_workflow(
        &pool,
        user,
        "retired-parent",
        &sub_workflow_graph(child),
        "archived",
        true,
    )
    .await;

    let scan = talos_child_workflow_refs::scan_child_parents(&pool, user, &[child])
        .await
        .expect("scan");
    assert!(
        scan.parents_of(child).is_empty(),
        "an archived parent dispatches nothing, so it protects nothing"
    );

    // The CONTROL: the same graph on a live parent DOES protect.
    let child2 = seed_workflow(&pool, user, "the-other-child", EMPTY_GRAPH, "active", true).await;
    seed_workflow(
        &pool,
        user,
        "live-parent",
        &sub_workflow_graph(child2),
        "active",
        true,
    )
    .await;
    let scan2 = talos_child_workflow_refs::scan_child_parents(&pool, user, &[child2])
        .await
        .expect("scan");
    assert_eq!(
        scan2.parents_of(child2),
        vec!["live-parent".to_string()],
        "the exclusion must not have swallowed the live case too"
    );
}

/// The boot-warmup twin, from the same home. An archived workflow's graph is
/// not worth pre-warming; a live one's is.
#[tokio::test]
async fn boot_warmup_skips_retired_workflows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());

    seed_workflow(
        &pool,
        user,
        "retired-warmup",
        r#"{"nodes":[{"id":"retired-marker"}],"edges":[]}"#,
        "archived",
        true,
    )
    .await;
    seed_workflow(
        &pool,
        user,
        "live-warmup",
        r#"{"nodes":[{"id":"live-marker"}],"edges":[]}"#,
        "active",
        true,
    )
    .await;

    let graphs = repo
        .list_enabled_graph_json_for_boot_warmup(100)
        .await
        .expect("warmup scan");
    let joined = graphs.join("\n");
    assert!(
        !joined.contains("retired-marker"),
        "a retired workflow's graph is not a warmup target"
    );
    assert!(
        joined.contains("live-marker"),
        "the control must still be warmed, or this proves nothing"
    );
}
