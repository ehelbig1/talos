//! A draft that runs as somebody's sub-workflow is not a stale draft.
//!
//! #758 taught the hygiene report's DORMANT section that a sub-workflow runs
//! in-process (`execute_subworkflow_graph`) and records no
//! `workflow_executions` row — measured 2026-09-05: ZERO rows carrying
//! `parent_execution_id` across the live table and the archive, platform-wide.
//! It classified the other two draft paths as latent, "no draft child on the
//! fleet". The FIRST live report after that deploy listed `cos-team-recall` —
//! the flagship `pa-chief-of-staff`'s daily `team_gather` sub-workflow, which
//! ran every day that week — under *"1 draft workflow(s) have never been
//! published or executed in 7+ days — likely scaffolding leftovers … delete
//! with `batch_delete_workflows`"*, two sections below the dormant list where
//! the SAME row was already annotated `runs_as_child_of:
//! ["pa-chief-of-staff"]`.
//!
//! Three paths run off that population, and they are not equally dangerous —
//! stating which is which is the point of these tests:
//!
//! 1. the report row + recommendation (advice a human reads);
//! 2. `fix_all`'s auto-delete set (an IRREVERSIBLE write behind one confirm);
//! 3. `session_start`'s auto-archive (an unattended write, reversible).
//!
//! Path 2 was blocked on the live fleet the day this was written — but by
//! `is_substantive_workflow`, an authored-INTENT predicate that asks whether a
//! human shaped the draft and knows nothing about who runs it. A child with a
//! bare graph was fully exposed. Every fix_all test below therefore seeds a
//! child whose graph is NOT substantive, so a green result cannot be the
//! coincidence rather than the guard.
//!
//! Every test comes with a positive control. An exclusion is only correct if a
//! GENUINELY abandoned draft is still listed, still counted, still deletable
//! and still archived — a test that only proves "the child is spared" would
//! pass on a tree where the whole feature had been deleted.
//!
//! DB tests on the `common` harness (each gets a template clone of the
//! migrated DB), so they belong in CTRL_TESTS, not TC_TESTS.

mod common;

use sqlx::{Pool, Postgres};
use std::sync::Arc;
use talos_analytics_repository::AnalyticsRepository;
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'draft child test')",
    )
    .bind(id)
    .bind(format!("draft-child-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// Seeded 60 days old so it clears BOTH windows: the stale-draft query's
/// `created_at < NOW() - INTERVAL '7 days'` and the dormant query's 30.
async fn seed_workflow(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    graph: &str,
    status: &str,
    enabled: bool,
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
    .bind(enabled)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_draft(pool: &Pool<Postgres>, user_id: Uuid, name: &str, graph: &str) -> Uuid {
    seed_workflow(pool, user_id, name, graph, "draft", true).await
}

async fn seed_published_parent(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    graph: &str,
) -> Uuid {
    seed_workflow(pool, user_id, name, graph, "published", true).await
}

/// A graph `is_substantive_workflow` reports as NOT substantive: one
/// non-structural node with empty `data`, no prompt, no schema, no retry, no
/// per-node metadata. Every fix_all assertion below rides on this — with a
/// substantive graph the test would pass on the pre-fix tree.
const BARE_GRAPH: &str = r#"{"nodes":[{"id":"n","type":"module","data":{}}],"edges":[]}"#;

fn sub_workflow_graph(child: Uuid) -> String {
    format!(
        r#"{{"nodes":[{{"id":"gather","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
    )
}

fn hygiene_service(pool: &Pool<Postgres>) -> talos_hygiene_service::HygieneService {
    talos_hygiene_service::HygieneService::new(
        Arc::new(AnalyticsRepository::new(pool.clone())),
        Arc::new(talos_workflow_repository::WorkflowRepository::new(
            pool.clone(),
        )),
        Arc::new(talos_execution_repository::ExecutionRepository::new(
            pool.clone(),
        )),
        Arc::new(talos_module_repository::ModuleRepository::new(pool.clone())),
    )
}

/// The report + fix candidates exactly as `get_platform_hygiene_report`
/// assembles them — the real planning path, not a re-derivation.
async fn hygiene_outcome(
    pool: &Pool<Postgres>,
    user_id: Uuid,
) -> talos_hygiene_service::HygieneReportOutcome {
    hygiene_service(pool)
        .generate(talos_hygiene_service::HygieneReportInput { user_id })
        .await
        .expect("hygiene report")
}

/// The draft cleanup recommendation, as an operator sees it.
fn draft_recommendation(report: &serde_json::Value) -> Option<serde_json::Value> {
    report
        .get("recommendations")?
        .as_array()?
        .iter()
        .find(|r| {
            r.get("action")
                .and_then(|a| a.as_str())
                .is_some_and(|a| a.contains("never been published or executed"))
        })
        .cloned()
}

fn names(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| {
                    x.get("name")
                        .or_else(|| x.get("workflow_id"))
                        .and_then(|n| n.as_str())
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn workflow_status(pool: &Pool<Postgres>, id: Uuid) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT status FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("status read")
}

// ─────────────── Path 1: the report row and the recommendation ───────────────

/// REPRODUCTION. On the pre-fix tree the child is listed with no annotation
/// and counted in an advice line naming `batch_delete_workflows`.
#[tokio::test]
async fn a_draft_sub_workflow_is_listed_with_its_parent_and_not_counted_for_deletion() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "cos-team-recall", BARE_GRAPH).await;
    seed_published_parent(&pool, user, "pa-chief-of-staff", &sub_workflow_graph(child)).await;
    // The control lives in the same report: a genuinely abandoned draft.
    seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let report = hygiene_outcome(&pool, user).await.report;
    let listed = report["stale_draft_workflows"]
        .as_array()
        .expect("stale draft list");

    // The child is STILL LISTED — an operator asking "what has never run?"
    // should see it, with the reason. Hiding it would be a different
    // misleading report.
    let row = listed
        .iter()
        .find(|r| r["name"] == "cos-team-recall")
        .expect("the child is still listed among drafts with no executions");
    assert_eq!(
        row["runs_as_child_of"],
        serde_json::json!(["pa-chief-of-staff"]),
        "the draft must name the enabled parent that dispatches into it"
    );
    assert!(
        row["excluded_from_cleanup_reason"].is_string(),
        "the row must say why it is not in the count below it"
    );

    let rec = draft_recommendation(&report).expect("the draft cleanup advice must still fire");
    assert_eq!(
        rec["affected_count"].as_i64(),
        Some(1),
        "only the abandoned draft is in the count"
    );
    assert_eq!(
        rec["deletable"],
        serde_json::json!(["abandoned-scaffold"]),
        "the flagship's daily sub-workflow was recommended for deletion"
    );
    assert_eq!(
        rec["excluded_child_workflows"].as_i64(),
        Some(1),
        "the exclusion must be DISCLOSED — a count that silently disagrees with the list \
         above it is its own misleading report"
    );
    assert!(
        rec["action"]
            .as_str()
            .unwrap_or_default()
            .contains("EXCLUDED"),
        "the prose must say why the count and the list disagree"
    );

    // The two populations overlap by construction (a 60-day-old draft child is
    // both dormant and stale), so they are disclosed as two counts, never one.
    let excl = &report["summary"]["child_workflow_exclusion"];
    assert_eq!(excl["excluded_stale_drafts_count"].as_i64(), Some(1));
    assert_eq!(
        excl["excluded_from_cleanup_count"].as_i64(),
        Some(1),
        "the dormant half keeps its own, unchanged denominator"
    );
}

/// The control the exclusion cannot supply on its own: with no child in play
/// the advice is byte-for-byte what it always was. Deleting the recommendation
/// entirely would pass the test above and fail this one.
#[tokio::test]
async fn a_genuinely_abandoned_draft_is_still_listed_and_counted() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let report = hygiene_outcome(&pool, user).await.report;
    let rec = draft_recommendation(&report).expect("advice fires");
    assert_eq!(rec["affected_count"].as_i64(), Some(1));
    assert_eq!(rec["excluded_child_workflows"].as_i64(), Some(0));
    assert!(
        !rec["action"]
            .as_str()
            .unwrap_or_default()
            .contains("EXCLUDED"),
        "with nothing excluded the advice must not claim an exclusion"
    );
    let row = report["stale_draft_workflows"][0].clone();
    assert!(
        row["runs_as_child_of"].is_null() && row["excluded_from_cleanup_reason"].is_null(),
        "an unreferenced draft gains no annotation: {row}"
    );
}

// ───────────────── Path 2: fix_all — the irreversible write ─────────────────

/// The planning half, driven through the REAL `fix_all` path with
/// `confirm=false`. `BARE_GRAPH` is deliberately not substantive, so
/// `is_substantive_workflow` cannot be what spares the child here.
#[tokio::test]
async fn a_draft_child_is_not_in_fix_alls_auto_delete_set() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "cos-team-recall", BARE_GRAPH).await;
    seed_published_parent(&pool, user, "pa-chief-of-staff", &sub_workflow_graph(child)).await;
    let orphan = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let outcome = hygiene_outcome(&pool, user).await;
    let preview = &outcome.fix_candidates.preview;

    assert_eq!(
        names(preview.get("stale_draft_workflows_to_delete")),
        vec!["abandoned-scaffold".to_string()],
        "the child is in fix_all's to-delete list: {preview}"
    );
    assert_eq!(
        names(preview.get("child_drafts_skipped")),
        vec!["cos-team-recall".to_string()],
        "the skip must be visible to the operator being asked to confirm"
    );
    assert!(
        preview["substantive_drafts_skipped"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "premise of this test: BARE_GRAPH is NOT substantive, so the authored-intent \
         predicate is not what spares the child"
    );
    assert_eq!(outcome.fix_candidates.draft_ids, vec![orphan]);
    assert!(!outcome.fix_candidates.draft_ids.contains(&child));
}

/// **The one that matters.** `confirm=true` against a real database: the
/// abandoned draft is GONE and the flagship's child is still there.
#[tokio::test]
async fn confirming_fix_all_deletes_the_orphan_and_leaves_the_child_alive() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "cos-team-recall", BARE_GRAPH).await;
    seed_published_parent(&pool, user, "pa-chief-of-staff", &sub_workflow_graph(child)).await;
    let orphan = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let svc = hygiene_service(&pool);
    let outcome = svc
        .generate(talos_hygiene_service::HygieneReportInput { user_id: user })
        .await
        .expect("hygiene report");
    let results = svc.apply_fixes(user, &outcome.fix_candidates).await;

    assert_eq!(
        results["results"]["stale_drafts_deleted"].as_i64(),
        Some(1),
        "the fix must still do its job: {results}"
    );
    assert!(
        workflow_status(&pool, orphan).await.is_none(),
        "the genuinely abandoned draft should have been deleted"
    );
    assert_eq!(
        workflow_status(&pool, child).await.as_deref(),
        Some("draft"),
        "confirm=true deleted the flagship's daily team_gather sub-workflow"
    );
}

// ───────────── Path 3: session_start's unattended auto-archive ─────────────

#[tokio::test]
async fn the_auto_archive_sweep_leaves_a_child_alone_and_archives_an_orphan() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "cos-team-recall", BARE_GRAPH).await;
    seed_published_parent(&pool, user, "pa-chief-of-staff", &sub_workflow_graph(child)).await;
    let orphan = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let repo = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let outcome = repo
        .archive_stale_drafts_excluding_children(user, 7)
        .await
        .expect("archive sweep");

    assert_eq!(outcome.archived, 1, "the orphan must still be archived");
    assert_eq!(
        outcome
            .skipped_children
            .iter()
            .map(|c| c.name.clone())
            .collect::<Vec<_>>(),
        vec!["cos-team-recall".to_string()],
        "the sweep must say what it held back — a sweep that silently declines \
         to act is its own misleading report"
    );
    assert_eq!(
        outcome.skipped_children[0].runs_as_child_of,
        vec!["pa-chief-of-staff".to_string()]
    );
    assert_eq!(
        workflow_status(&pool, orphan).await.as_deref(),
        Some("archived")
    );
    assert_eq!(
        workflow_status(&pool, child).await.as_deref(),
        Some("draft"),
        "session_start archived the flagship's daily sub-workflow"
    );
}

/// The guard is keyed on an ENABLED parent, exactly as #758's is: a child
/// whose only parent is disabled genuinely IS abandoned, and the sweep must
/// still reach it — otherwise "referenced anywhere, ever" becomes a permanent
/// immunity.
#[tokio::test]
async fn a_draft_child_of_a_disabled_parent_is_still_archived() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "orphaned-child", BARE_GRAPH).await;
    seed_workflow(
        &pool,
        user,
        "retired-parent",
        &sub_workflow_graph(child),
        "published",
        false, // disabled
    )
    .await;

    let repo = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let outcome = repo
        .archive_stale_drafts_excluding_children(user, 7)
        .await
        .expect("archive sweep");
    assert_eq!(outcome.archived, 1);
    assert!(outcome.skipped_children.is_empty());
    assert_eq!(
        workflow_status(&pool, child).await.as_deref(),
        Some("archived")
    );
}

/// The refusal that #758 could not reach: `stale_days <= 0` still archives
/// nothing, and the sweep is a no-op rather than a user-wide wipe (MCP-1062).
#[tokio::test]
async fn a_non_positive_window_still_archives_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let draft = seed_draft(&pool, user, "fresh-scaffold", BARE_GRAPH).await;

    let repo = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let outcome = repo
        .archive_stale_drafts_excluding_children(user, 0)
        .await
        .expect("archive sweep");
    assert_eq!(outcome.archived, 0);
    assert_eq!(
        workflow_status(&pool, draft).await.as_deref(),
        Some("draft")
    );
}

// ─────────────── The delete-time guard: the last line of defence ───────────────

/// Every guard above lives in a report that RECOMMENDS calling
/// `batch_delete_workflows`. This one is on the write itself — the reference
/// lives in `graph_json` as TEXT, so no foreign key can express it.
#[tokio::test]
async fn deleting_a_workflow_an_enabled_parent_dispatches_into_is_refused() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "cos-team-recall", BARE_GRAPH).await;
    seed_published_parent(&pool, user, "pa-chief-of-staff", &sub_workflow_graph(child)).await;
    let orphan = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let outcome = repo
        .delete_workflows_checked(&[child, orphan], user)
        .await
        .expect("delete");

    assert_eq!(
        outcome.deleted,
        vec![orphan],
        "an unreferenced workflow must still delete"
    );
    assert_eq!(outcome.blocked_referenced.len(), 1);
    assert_eq!(outcome.blocked_referenced[0].id, child);
    assert_eq!(
        outcome.blocked_referenced[0].parents,
        vec!["pa-chief-of-staff".to_string()]
    );
    assert!(
        outcome.blocked_referenced[0]
            .reason
            .contains("pa-chief-of-staff"),
        "the refusal must name the parent so the operator can act on it"
    );
    assert_eq!(
        workflow_status(&pool, child).await.as_deref(),
        Some("draft")
    );
    assert!(workflow_status(&pool, orphan).await.is_none());
}

/// Deleting a parent and its child in ONE call is coherent and must work —
/// otherwise a retired workflow tree becomes undeletable and the guard is a
/// trap rather than a safeguard.
#[tokio::test]
async fn a_parent_deleted_in_the_same_call_does_not_block_its_child() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "retired-child", BARE_GRAPH).await;
    let parent =
        seed_published_parent(&pool, user, "retired-parent", &sub_workflow_graph(child)).await;

    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let outcome = repo
        .delete_workflows_checked(&[child, parent], user)
        .await
        .expect("delete");

    assert!(
        outcome.blocked_referenced.is_empty(),
        "the only parent is itself being deleted: {:?}",
        outcome.blocked_referenced
    );
    assert_eq!(outcome.deleted.len(), 2);
    assert!(workflow_status(&pool, child).await.is_none());
    assert!(workflow_status(&pool, parent).await.is_none());
}

/// A published (non-draft) child is protected too. The guard is about who
/// DISPATCHES the workflow, not about its status — the same reason the
/// dormant list needed it at 30 days and this list needs it at 7.
#[tokio::test]
async fn a_published_child_is_protected_from_deletion_too() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let judge = seed_published_parent(&pool, user, "pa-quality-judge", BARE_GRAPH).await;
    let graph = format!(
        r#"{{"nodes":[{{"id":"j","type":"system:judge","data":{{"judge_workflow_id":"{judge}"}}}}],"edges":[]}}"#
    );
    seed_published_parent(&pool, user, "pa-daily-brief", &graph).await;

    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let outcome = repo
        .delete_workflows_checked(&[judge], user)
        .await
        .expect("delete");
    assert!(outcome.deleted.is_empty());
    assert_eq!(outcome.blocked_referenced.len(), 1);
}

// ───────────────────────── UNKNOWN is not EMPTY ─────────────────────────

/// A parent whose graph does not parse asserts NO reference — so the report
/// names no parent for the draft it mentions — but every DECISION holds that
/// draft back anyway, because "I could not read the parent" is not "no parent
/// dispatches into it". The two surfaces disagree deliberately.
#[tokio::test]
async fn a_draft_mentioned_by_an_unreadable_parent_is_listed_but_never_acted_on() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "maybe-a-child", BARE_GRAPH).await;
    // Parses as JSON but carries no `nodes` array => UNKNOWN, and mentions the
    // candidate's id in its text so the scan's prefilter returns it.
    let broken = format!(r#"{{"note": "dispatches {child}"}}"#);
    seed_published_parent(&pool, user, "half-written-parent", &broken).await;
    let orphan = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    // Report: listed, no parent claimed, but flagged as excluded.
    let outcome = hygiene_outcome(&pool, user).await;
    let row = outcome.report["stale_draft_workflows"]
        .as_array()
        .expect("list")
        .iter()
        .find(|r| r["name"] == "maybe-a-child")
        .expect("still listed")
        .clone();
    assert!(
        row["runs_as_child_of"].is_null(),
        "an unreadable parent asserts no reference: {row}"
    );
    assert!(
        row["excluded_from_cleanup_reason"].is_string(),
        "…but the row must say it was held back and why: {row}"
    );
    assert_eq!(
        outcome.report["summary"]["child_workflow_exclusion"]["unreadable_parents"],
        serde_json::json!(["half-written-parent"]),
        "the incompleteness travels to the caller by NAME"
    );

    // Decision 1: fix_all.
    assert_eq!(outcome.fix_candidates.draft_ids, vec![orphan]);

    // Decision 2: the auto-archive sweep.
    let advanced = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let archive = advanced
        .archive_stale_drafts_excluding_children(user, 7)
        .await
        .expect("archive sweep");
    assert_eq!(archive.archived, 1, "the orphan is still archived");
    assert_eq!(archive.unreadable_parents, vec!["half-written-parent"]);
    assert_eq!(
        workflow_status(&pool, child).await.as_deref(),
        Some("draft")
    );

    // Decision 3: the delete-time guard.
    let wf_repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let del = wf_repo
        .delete_workflows_checked(&[child], user)
        .await
        .expect("delete");
    assert!(del.deleted.is_empty());
    assert_eq!(del.blocked_referenced.len(), 1);
    assert!(
        del.blocked_referenced[0].reason.contains("UNKNOWN"),
        "the refusal must say the evidence is an unreadable parent, not a known reference: {}",
        del.blocked_referenced[0].reason
    );
}

/// The control for the test above: a parent that parses and names nobody
/// leaves every candidate deletable. Without this, "protect on anything
/// unexpected" would pass the test above while protecting everything.
#[tokio::test]
async fn a_readable_parent_that_names_nobody_protects_nobody() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let draft = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;
    // Mentions the id in a config VALUE, not through a child-dispatch key —
    // the `LIKE` prefilter returns it and the Rust parse rejects it.
    let graph = format!(
        r#"{{"nodes":[{{"id":"n","type":"module","data":{{"NOTE":"see {draft}"}}}}],"edges":[]}}"#
    );
    seed_published_parent(&pool, user, "mentions-it-in-prose", &graph).await;

    let outcome = hygiene_outcome(&pool, user).await;
    assert_eq!(
        outcome.fix_candidates.draft_ids,
        vec![draft],
        "a uuid in an unrelated field is not a dispatch reference"
    );

    let wf_repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let del = wf_repo
        .delete_workflows_checked(&[draft], user)
        .await
        .expect("delete");
    assert_eq!(del.deleted, vec![draft]);
    assert!(del.blocked_referenced.is_empty());
}
