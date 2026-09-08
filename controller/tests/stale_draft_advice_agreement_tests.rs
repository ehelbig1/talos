//! The advice must agree with the decision it recommends.
//!
//! `get_platform_hygiene_report` renders TWO statements about one population.
//! The stale-draft cleanup RECOMMENDATION counts rows and names
//! `batch_delete_workflows`; `fix_all` — built on the SAME rows, in the SAME
//! crate — partitions them into what it will delete and what it refuses. Since
//! M-I (2026-05-06) `fix_all` has refused a SUBSTANTIVE draft: an operator
//! running `confirm=true` right after reading `session_start`'s "N substantive
//! draft(s) ready for publish_version" would otherwise have deleted exactly the
//! workflows they were about to ship.
//!
//! The recommendation never learned that. #760 taught it about CHILD drafts —
//! a draft an enabled parent dispatches into — and left the substantive
//! blindness in place, so on the pre-fix tree one report says, of one row:
//!
//!   * recommendation: counted in `affected_count`, named in `deletable`,
//!     "likely scaffolding leftovers … delete with `batch_delete_workflows`";
//!   * `fix_all` preview: `substantive_drafts_skipped`, "auto-delete refused".
//!
//! An operator who follows the advice gets a refusal from the tool the advice
//! named, or — worse, since `batch_delete_workflows` has no such guard —
//! deletes a workflow the platform's own decision path was protecting.
//!
//! `the_advice_and_the_decision_agree_about_every_stale_draft` drives BOTH
//! paths over ONE report and fails on pristine main by assertion. It is also
//! the mutation detector in both directions: make the recommendation ignore the
//! substantive exclusion and `deletable` gains a row `fix_all` refuses; make
//! `fix_all` ignore it and `stale_draft_workflows_to_delete` gains a row the
//! advice excludes. Either way the same test fails, and the assertion that
//! fires names which side moved.
//!
//! Every exclusion test carries a positive control in the same report: a
//! genuinely abandoned scaffold must still be counted, still be named
//! `deletable`, and still be in `fix_all`'s delete set. A test that only proves
//! "the substantive draft is spared" would pass on a tree where the whole
//! recommendation had been deleted.
//!
//! DB tests on the `common` harness (each gets a template clone of the migrated
//! DB), so they belong in CTRL_TESTS, not TC_TESTS (sub-leg 64b).

mod common;

use sqlx::{Pool, Postgres};
use std::sync::Arc;
use talos_analytics_repository::AnalyticsRepository;
use uuid::Uuid;

/// A graph `is_substantive_workflow` reports as NOT substantive: one
/// non-structural node with empty `data`, no prompt, no schema, no retry, no
/// per-node metadata.
const BARE_GRAPH: &str = r#"{"nodes":[{"id":"n","type":"module","data":{}}],"edges":[]}"#;

/// Substantive via the `retry_count` marker — one of the exact markers
/// `is_substantive_workflow`'s own unit tests accept — on an otherwise BARE
/// node, so nothing here passes because the graph merely looks finished.
const SUBSTANTIVE_GRAPH: &str =
    r#"{"nodes":[{"id":"n","type":"module","data":{},"retry_count":3}],"edges":[]}"#;

/// Substantive via a long `SYSTEM_PROMPT` (>200 chars), the second marker
/// family — so the agreement is a property of the predicate, not of one field.
fn prompt_graph() -> String {
    let prompt = "you are a careful assistant. ".repeat(12); // > 200 chars
    format!(
        r#"{{"nodes":[{{"id":"n","type":"llm","data":{{"SYSTEM_PROMPT":"{prompt}"}}}}],"edges":[]}}"#
    )
}

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'draft advice test')",
    )
    .bind(id)
    .bind(format!("draft-advice-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// Seeded 60 days old so it clears the stale-draft query's
/// `created_at < NOW() - INTERVAL '7 days'` window.
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
        None,
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

fn strings(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn preview_names(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| x["name"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

// ───────────────────────── The contradiction itself ─────────────────────────

/// **REPRODUCTION and mutation detector, in one test over one report.**
///
/// Three drafts, one of each kind, so both the exclusions and the control are
/// exercised by the same call. Fails on pristine main at the first assertion
/// below (`deletable` is `["abandoned-scaffold", "half-built-brief"]` where
/// `fix_all` will delete only `abandoned-scaffold`).
#[tokio::test]
async fn the_advice_and_the_decision_agree_about_every_stale_draft() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    let child = seed_draft(&pool, user, "cos-team-recall", BARE_GRAPH).await;
    seed_workflow(
        &pool,
        user,
        "pa-chief-of-staff",
        &sub_workflow_graph(child),
        "published",
    )
    .await;
    seed_draft(&pool, user, "half-built-brief", SUBSTANTIVE_GRAPH).await;
    seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let outcome = hygiene_outcome(&pool, user).await;
    let rec = draft_recommendation(&outcome.report).expect("the draft cleanup advice must fire");
    let preview = &outcome.fix_candidates.preview;

    // (a) The advice's list and the tool's action are the SAME set. This is the
    // whole package: two statements about one population, in one response.
    assert_eq!(
        sorted(strings(rec.get("deletable"))),
        sorted(preview_names(
            preview.get("stale_draft_workflows_to_delete")
        )),
        "the advice names rows fix_all refuses, or refuses rows the advice names.\n\
         advice `deletable`: {}\n\
         fix_all to-delete:  {}",
        rec["deletable"],
        preview["stale_draft_workflows_to_delete"],
    );

    // (b) …and the count agrees with the list it is a count OF.
    assert_eq!(
        rec["affected_count"].as_i64(),
        Some(strings(rec.get("deletable")).len() as i64),
        "affected_count must count the deletable set and nothing else"
    );

    // (c) The control, in the same report: the genuinely abandoned scaffold is
    // still counted, still named, still deleted. Without this, deleting the
    // recommendation outright would pass (a) and (b).
    assert_eq!(
        strings(rec.get("deletable")),
        vec!["abandoned-scaffold".to_string()],
        "the abandoned scaffold must still be recommended for deletion"
    );
    assert_eq!(rec["affected_count"].as_i64(), Some(1));

    // (d) The two exclusions are DISCLOSED and distinguishable — a count that
    // silently disagrees with the list above it is its own misleading report.
    assert_eq!(
        rec["excluded_substantive_drafts"].as_i64(),
        Some(1),
        "the substantive exclusion must be disclosed beside the child one"
    );
    assert_eq!(rec["excluded_child_workflows"].as_i64(), Some(1));
    assert_eq!(
        strings(rec.get("publishable")),
        vec!["half-built-brief".to_string()],
        "the report row carries no substantive marker, so `publishable` is the only place \
         an operator can see WHICH listed draft the count left out"
    );

    // (e) The prose says why count and list disagree, in both vocabularies.
    let action = rec["action"].as_str().unwrap_or_default();
    assert!(
        action.contains("publish_version, not deletion"),
        "the advice must say what to do with the excluded substantive draft: {action}"
    );
    assert!(
        action.contains("no marker of authored intent"),
        "\"likely scaffolding leftovers\" is now only true of the deletable subset, and the \
         sentence must say so: {action}"
    );

    // (f) The report still LISTS all three. An exclusion that hid rows would be
    // a different misleading report.
    let listed: Vec<String> = outcome.report["stale_draft_workflows"]
        .as_array()
        .expect("stale draft list")
        .iter()
        .map(|r| r["name"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(sorted(listed).len(), 3, "every stale draft stays listed");

    // (g) fix_all's own buckets are unchanged in meaning and still partition.
    assert_eq!(
        preview_names(preview.get("substantive_drafts_skipped")),
        vec!["half-built-brief".to_string()]
    );
    assert_eq!(
        preview_names(preview.get("child_drafts_skipped")),
        vec!["cos-team-recall".to_string()]
    );
}

/// The narrow reproduction, with no child in play: pre-fix, ONE substantive
/// draft was counted `1` and named `deletable` by the advice while `fix_all`
/// deleted nothing at all. This is the shape an operator on a fleet with no
/// sub-workflows would have hit.
#[tokio::test]
async fn a_substantive_draft_is_not_advertised_as_deletable() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;

    seed_draft(&pool, user, "half-built-brief", SUBSTANTIVE_GRAPH).await;
    seed_draft(&pool, user, "long-prompt-draft", &prompt_graph()).await;
    seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let outcome = hygiene_outcome(&pool, user).await;
    let rec = draft_recommendation(&outcome.report).expect("advice fires");

    assert_eq!(rec["affected_count"].as_i64(), Some(1));
    assert_eq!(
        strings(rec.get("deletable")),
        vec!["abandoned-scaffold".to_string()]
    );
    assert_eq!(rec["excluded_substantive_drafts"].as_i64(), Some(2));
    assert_eq!(
        sorted(strings(rec.get("publishable"))),
        vec![
            "half-built-brief".to_string(),
            "long-prompt-draft".to_string()
        ],
        "both authored-intent marker families must be excluded, not just retry_count"
    );
    assert_eq!(
        rec["excluded_child_workflows"].as_i64(),
        Some(0),
        "no child is in play; the child disclosure must not borrow this exclusion"
    );
    assert!(
        !rec["action"]
            .as_str()
            .unwrap_or_default()
            .contains("an enabled parent dispatches into them"),
        "with no child excluded the advice must not claim a child exclusion"
    );
    assert_eq!(
        outcome.fix_candidates.draft_ids.len(),
        1,
        "fix_all still deletes exactly the scaffold"
    );
}

/// The control the exclusion cannot supply on its own: with nothing excluded,
/// the advice is what it always was and claims no exclusion. A tree that
/// hard-coded `excluded_substantive_drafts` or always appended the clause would
/// pass the tests above and fail this one.
#[tokio::test]
async fn with_nothing_excluded_the_advice_claims_no_exclusion() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    seed_draft(&pool, user, "abandoned-scaffold", BARE_GRAPH).await;

    let outcome = hygiene_outcome(&pool, user).await;
    let rec = draft_recommendation(&outcome.report).expect("advice fires");

    assert_eq!(rec["affected_count"].as_i64(), Some(1));
    assert_eq!(rec["excluded_substantive_drafts"].as_i64(), Some(0));
    assert_eq!(rec["excluded_child_workflows"].as_i64(), Some(0));
    assert_eq!(strings(rec.get("publishable")), Vec::<String>::new());
    let action = rec["action"].as_str().unwrap_or_default();
    assert!(
        !action.contains("EXCLUDED"),
        "with nothing excluded the advice must not claim an exclusion: {action}"
    );
    assert!(
        action.contains("no marker of authored intent"),
        "the population qualifier is unconditional — it describes what the count IS, not \
         what was excluded: {action}"
    );
}

/// A report whose every stale draft is substantive emits NO delete advice —
/// deliberately, and by the same rule #760 applied to dormant children: a
/// cleanup recommendation whose deletable set is empty has nothing to
/// recommend. The rows stay listed and `session_start` still points at
/// `publish_version`, so the operator is not left uninformed; what disappears
/// is an instruction the platform would have refused.
#[tokio::test]
async fn an_all_substantive_population_produces_no_delete_advice() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    seed_draft(&pool, user, "half-built-brief", SUBSTANTIVE_GRAPH).await;

    let outcome = hygiene_outcome(&pool, user).await;
    assert!(
        draft_recommendation(&outcome.report).is_none(),
        "advice with an empty deletable set must not fire: {}",
        outcome.report["recommendations"]
    );
    assert_eq!(
        outcome.report["stale_draft_workflows"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "the row is still LISTED — the report never hides a finding, it only declines to \
         recommend acting on it"
    );
    assert!(
        outcome.fix_candidates.draft_ids.is_empty(),
        "and fix_all deletes nothing, which is what it always did"
    );
    assert_eq!(
        preview_names(
            outcome
                .fix_candidates
                .preview
                .get("substantive_drafts_skipped")
        ),
        vec!["half-built-brief".to_string()]
    );
}
