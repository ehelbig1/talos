//! `session_start` must not archive what it just told you to publish.
//!
//! In 2026-05 (M-I) `fix_all` was taught to SKIP a "substantive" draft —
//! `talos_draft_heuristics::is_substantive_workflow`, an authored-INTENT
//! predicate: a draft a human visibly shaped is not scaffolding, and
//! `session_start`'s own display lists such drafts under
//! `unpublished_substantive_drafts` with
//! `next_step: "publish_version with workflow_id=…"`. The unattended
//! ARCHIVE path was never taught the same rule, so an operator who ran
//! `session_start(auto_archive_stale_days: N)` after reading that list
//! archived exactly what it recommended shipping — and, because the display
//! was read BEFORE the sweep, in the SAME response.
//!
//! Measured on pristine `origin/main` 2026-09-05: the brief listed the draft
//! as publishable and reported `auto_archived_stale_drafts: 1` for it.
//!
//! #760 routed this path through the child scan and left the substantive rule
//! out, recording it rather than attempting it because archiving is
//! reversible. This is that remainder.
//!
//! Every test carries a positive control. An exclusion is only correct if a
//! genuinely abandoned stub is still archived — a test that only proves "the
//! shaped draft survives" would pass on a tree where the sweep had been
//! deleted outright.
//!
//! DB tests on the `common` harness (each gets a template clone of the
//! migrated DB), so they belong in CTRL_TESTS, not TC_TESTS (check 64b).

mod common;

use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

/// Substantive by BOTH branches: every non-structural node has non-empty
/// `data`, and one node carries a `description`. The shape
/// `is_substantive_workflow`'s own unit tests accept, and the shape the live
/// fleet's only stale-draft candidate has (`cos-team-recall` carries
/// `retry_count: 2`).
const SHAPED_GRAPH: &str = r#"{"nodes":[{"id":"n","type":"module","description":"pull the weekly numbers","data":{"MODULE":"http"}}],"edges":[]}"#;
/// NOT substantive: one non-structural node, empty `data`, no marker of any
/// kind. Every positive control below rides on this.
const BARE_GRAPH: &str = r#"{"nodes":[{"id":"n","type":"module","data":{}}],"edges":[]}"#;
/// Substantive by BRANCH 1 ONLY: every non-structural node has non-empty
/// `data`, and no node carries a prompt / schema / retry / per-node marker.
const CONFIGURED_ONLY_GRAPH: &str =
    r#"{"nodes":[{"id":"n","type":"module","data":{"MODULE":"http"}}],"edges":[]}"#;
/// Substantive by BRANCH 2 ONLY: `data` is present but the node is
/// "unconfigured" by the coarse check, and authored intent shows up as
/// `retry_count`. This is the live fleet's real shape — see the test that uses
/// it for why that matters.
const RETRY_ONLY_GRAPH: &str =
    r#"{"nodes":[{"id":"n","type":"module","data":{},"retry_count":2}],"edges":[]}"#;
/// Not parseable as JSON at all. `workflows.graph_json` is `text NOT NULL`,
/// so this is storable — and "I could not read the graph" is not evidence
/// that nobody shaped it.
const UNREADABLE_GRAPH: &str = "this is not json";

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'substantive draft test')",
    )
    .bind(id)
    .bind(format!("substantive-draft-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// 60 days old so it clears any window these tests use.
async fn seed_workflow(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    graph: &str,
    status: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled, created_at) \
         VALUES ($1, $2, $3, $4, 'talos://t', $5, true, NOW() - INTERVAL '60 days')",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(graph)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_draft(pool: &Pool<Postgres>, user_id: Uuid, name: &str, graph: &str) -> Uuid {
    seed_workflow(pool, user_id, name, graph, "draft").await
}

fn sub_workflow_graph(child: Uuid) -> String {
    format!(
        r#"{{"nodes":[{{"id":"gather","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
    )
}

async fn workflow_status(pool: &Pool<Postgres>, id: Uuid) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT status FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("status read")
}

fn repo(pool: &Pool<Postgres>) -> talos_advanced_repository::AdvancedRepository {
    talos_advanced_repository::AdvancedRepository::new(pool.clone())
}

/// The whole brief, from the REAL service the MCP handler calls — not a
/// re-derivation of its two lists.
async fn brief(pool: &Pool<Postgres>, user_id: Uuid, days: Option<i64>) -> serde_json::Value {
    talos_session_brief_service::SessionBriefService::new(Arc::new(repo(pool)))
        .build(talos_session_brief_service::SessionBriefInput {
            user_id,
            auto_archive_days: days,
            server_version: "test".into(),
            build_time: "test".into(),
            static_tool_count: 0,
        })
        .await
        .expect("session brief")
        .report
}

fn ids_in(report: &serde_json::Value, key: &str) -> Vec<String> {
    report
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    e.get("workflow_id")
                        .or_else(|| e.get("id"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

// ───────────────────────── F1: the reproduction ─────────────────────────

/// REPRODUCTION, repository level. On pristine `origin/main` this sweep
/// returned `archived: 1` and left the row `archived`.
#[tokio::test]
async fn the_sweep_leaves_a_draft_a_human_shaped_alone_and_says_why() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let shaped = seed_draft(&pool, user, "weekly-numbers", SHAPED_GRAPH).await;
    let stub = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let outcome = repo(&pool)
        .archive_stale_drafts_excluding_children(user, 7)
        .await
        .expect("archive sweep");

    // The positive control comes FIRST: a green result must not be reachable
    // by the sweep having stopped working.
    assert_eq!(outcome.archived, 1, "the stub must still be archived");
    assert_eq!(
        workflow_status(&pool, stub).await.as_deref(),
        Some("archived")
    );

    assert_eq!(
        workflow_status(&pool, shaped).await.as_deref(),
        Some("draft"),
        "session_start archived a draft it simultaneously calls ready to publish"
    );
    assert_eq!(
        outcome
            .skipped_substantive
            .iter()
            .map(|d| d.name.clone())
            .collect::<Vec<_>>(),
        vec!["weekly-numbers".to_string()],
        "a sweep that silently declines to act is its own misleading report"
    );
    assert!(
        outcome.skipped_children.is_empty(),
        "nothing dispatches into it — the child rule must not be what spares it"
    );
}

/// THE POINT. One `session_start` response cannot both recommend
/// `publish_version` for a workflow and archive it. Disjointness by
/// construction, driven through the real service.
#[tokio::test]
async fn one_response_never_both_recommends_and_archives_the_same_draft() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let shaped = seed_draft(&pool, user, "weekly-numbers", SHAPED_GRAPH).await;
    let stub = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let report = brief(&pool, user, Some(7)).await;

    // Premise: the brief really does recommend publishing it, in this very
    // response. Without this the disjointness assertion below is vacuous.
    let recommended = ids_in(&report, "unpublished_substantive_drafts");
    assert!(
        recommended.contains(&shaped.to_string()),
        "premise failed — the brief did not recommend publishing the shaped draft: {report:#}"
    );

    assert_eq!(
        workflow_status(&pool, shaped).await.as_deref(),
        Some("draft"),
        "the SAME response recommends publish_version and archived it; \
         auto_archived_stale_drafts={:?}",
        report["auto_archived_stale_drafts"]
    );

    // Disjointness, stated as the response states it: nothing this call
    // archived may appear in EITHER draft list. The stub is the positive
    // control — it was archived, and it is therefore absent from both.
    assert_eq!(report["auto_archived_stale_drafts"].as_i64(), Some(1));
    assert_eq!(
        workflow_status(&pool, stub).await.as_deref(),
        Some("archived")
    );
    let listed: Vec<String> = ids_in(&report, "unpublished_substantive_drafts")
        .into_iter()
        .chain(ids_in(&report, "in_progress_drafts"))
        .collect();
    assert!(
        !listed.contains(&stub.to_string()),
        "a row this response archived is still listed as a draft to work on: {listed:?}"
    );

    // And the skip is DISCLOSED, with the reason, so the operator can see why
    // the count and the eligible population disagree.
    let skipped = ids_in(&report, "auto_archive_skipped_substantive");
    assert_eq!(skipped, vec![shaped.to_string()], "{report:#}");
    assert!(report["auto_archive_note"].is_string());
}

// ───────────────── The two reasons must stay distinguishable ─────────────────

/// A draft that is BOTH a live child and substantive is reported as a CHILD —
/// #760's order, mirroring `fix_all`'s partition. The reasons must not
/// collapse into one bucket: publishing this draft retires the substantive
/// reason and leaves the child reason standing.
#[tokio::test]
async fn a_shaped_child_is_reported_under_the_child_reason_not_the_shaped_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "cos-team-recall", SHAPED_GRAPH).await;
    seed_workflow(
        &pool,
        user,
        "pa-chief-of-staff",
        &sub_workflow_graph(child),
        "published",
    )
    .await;

    let outcome = repo(&pool)
        .archive_stale_drafts_excluding_children(user, 7)
        .await
        .expect("archive sweep");

    assert_eq!(outcome.archived, 0);
    assert_eq!(
        outcome
            .skipped_children
            .iter()
            .map(|c| c.name.clone())
            .collect::<Vec<_>>(),
        vec!["cos-team-recall".to_string()]
    );
    assert!(
        outcome.skipped_substantive.is_empty(),
        "a draft is reported under ONE reason; the child one wins"
    );
    assert_eq!(
        outcome.skipped_children[0].runs_as_child_of,
        vec!["pa-chief-of-staff".to_string()]
    );
    assert_ne!(
        outcome.skipped_children[0].reason,
        talos_draft_heuristics::DraftIntent::Substantive
            .cleanup_block_reason()
            .unwrap(),
        "the two reasons must read differently to an operator"
    );
}

/// UNKNOWN is not NO. A graph that will not parse says nothing about whether a
/// human shaped the draft, and this path WRITES — so it is held back under its
/// own reason rather than swept with the stubs.
#[tokio::test]
async fn an_unreadable_graph_is_held_back_under_its_own_reason() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let opaque = seed_draft(&pool, user, "corrupt-graph", UNREADABLE_GRAPH).await;
    let stub = seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let outcome = repo(&pool)
        .archive_stale_drafts_excluding_children(user, 7)
        .await
        .expect("archive sweep");

    assert_eq!(outcome.archived, 1, "the stub must still be archived");
    assert_eq!(
        workflow_status(&pool, stub).await.as_deref(),
        Some("archived")
    );
    assert_eq!(
        workflow_status(&pool, opaque).await.as_deref(),
        Some("draft")
    );
    assert_eq!(
        outcome
            .skipped_substantive
            .iter()
            .map(|d| d.reason.clone())
            .collect::<Vec<_>>(),
        vec![talos_draft_heuristics::DraftIntent::Unreadable
            .cleanup_block_reason()
            .unwrap()
            .to_string()],
        "an unreadable graph must not borrow the 'a human shaped this' reason"
    );
}

// ─────────────────────────── Positive controls ───────────────────────────

/// The sweep still does its job on a fleet of pure scaffolding, and says
/// nothing about exclusions it did not make.
#[tokio::test]
async fn a_fleet_of_stubs_is_swept_with_no_exclusions_claimed() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    for i in 0..3 {
        seed_draft(&pool, user, &format!("scaffold-{i}"), BARE_GRAPH).await;
    }

    let report = brief(&pool, user, Some(7)).await;
    assert_eq!(report["auto_archived_stale_drafts"].as_i64(), Some(3));
    assert!(
        report.get("auto_archive_skipped_substantive").is_none(),
        "absence is the all-clear; an empty list would still be a claim"
    );
    assert!(report.get("auto_archive_note").is_none());
}

/// The exclusion is about the SWEEP, not about visibility: a shaped draft the
/// sweep declined to archive is still listed, still recommended for
/// publishing, and still counted — the report/decision split #760 established.
#[tokio::test]
async fn a_skipped_draft_is_still_listed_and_still_recommended() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let shaped = seed_draft(&pool, user, "weekly-numbers", SHAPED_GRAPH).await;

    let report = brief(&pool, user, Some(7)).await;
    assert_eq!(
        ids_in(&report, "unpublished_substantive_drafts"),
        vec![shaped.to_string()]
    );
    let entry = &report["unpublished_substantive_drafts"][0];
    assert_eq!(entry["is_substantive"].as_bool(), Some(true));
    assert!(entry["next_step"]
        .as_str()
        .is_some_and(|s| s.starts_with("publish_version")));
}

/// ONE predicate, two surfaces. The brief's DISPLAY split and the sweep's
/// EXCLUSION must answer identically for the same row — the property the old
/// inline copy in `talos-session-brief-service` could only assert.
///
/// The shapes are chosen to separate the predicate's TWO branches, because a
/// test that only seeds rows both branches agree on cannot see a drift. This
/// was measured, not assumed: the first version of this test seeded only a
/// both-branches row and a bare row, and a mutation reducing the display half
/// to branch 1 alone SURVIVED it. `RETRY_ONLY_GRAPH` is the branch-2-only
/// shape — and it is the shape the live fleet's one stale-draft candidate
/// actually has (`cos-team-recall`, `retry_count: 2` on a node whose `data`
/// holds only `max_fuel`), so the case the old test could not see is the case
/// production is made of.
#[tokio::test]
async fn the_display_split_and_the_sweep_agree_on_every_shape() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let both = seed_draft(&pool, user, "both-branches", SHAPED_GRAPH).await;
    let branch1 = seed_draft(&pool, user, "configured-only", CONFIGURED_ONLY_GRAPH).await;
    let branch2 = seed_draft(&pool, user, "retry-only", RETRY_ONLY_GRAPH).await;
    let stub = seed_draft(&pool, user, "stub", BARE_GRAPH).await;
    let empty = seed_draft(&pool, user, "empty", r#"{"nodes":[],"edges":[]}"#).await;

    // Read the display WITHOUT sweeping, so both lists see all five rows.
    let listed = brief(&pool, user, None).await;
    let mut publishable = ids_in(&listed, "unpublished_substantive_drafts");
    publishable.sort();
    let mut expected = vec![both.to_string(), branch1.to_string(), branch2.to_string()];
    expected.sort();
    assert_eq!(
        publishable, expected,
        "display: every authored-intent shape is publishable, whichever branch says so"
    );
    let stubs = ids_in(&listed, "in_progress_drafts");
    assert!(stubs.contains(&stub.to_string()) && stubs.contains(&empty.to_string()));

    // Now sweep: exactly the display's stub half is archived, and exactly its
    // publishable half is held back.
    let outcome = repo(&pool)
        .archive_stale_drafts_excluding_children(user, 7)
        .await
        .expect("archive sweep");
    assert_eq!(outcome.archived, 2);
    let mut skipped: Vec<Uuid> = outcome.skipped_substantive.iter().map(|d| d.id).collect();
    skipped.sort();
    let mut shaped_ids = vec![both, branch1, branch2];
    shaped_ids.sort();
    assert_eq!(
        skipped, shaped_ids,
        "the sweep and the display must partition the same rows the same way"
    );
}
