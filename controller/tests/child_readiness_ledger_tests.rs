//! A child's reliability and freshness are MEASURABLE once the ledger can see
//! them — RFC 0012 P2.
//!
//! #762 taught three readiness scorers to say "unmeasurable" instead of zero,
//! by shrinking the denominator to `CHILD_MEASURABLE_MAX` (30) and naming what
//! could not be measured. That was the right answer while nothing could
//! measure it. RFC 0012 P1 built the thing that can — `sub_workflow_runs` —
//! and this phase teaches the scorers to read it.
//!
//! WHAT THESE TESTS ARE, STATED PRECISELY. **Every test here pins NEW
//! behaviour.** `ReadinessBasis::LedgerMeasured`, `ChildLedgerEvidence`,
//! `child_ledger_evidence` and `ChildRunLedger::child_run_stats_since` do not
//! exist on pristine `origin/main`, so there is no main-vocabulary twin to run
//! — a "fails on main" claim here would fail by COMPILE ERROR, which is worth
//! nothing. The burden is carried by MUTATION instead, and each test names the
//! mutation that turns it red; the results are recorded in `AGENT_NOTES.md`.
//!
//! What these tests DO drive is real production code against a real Postgres:
//! the real `ChildRunLedger` reads over the real table under its real RLS
//! policy, the real `child_ledger_evidence` window arithmetic, the real
//! `ReadinessBasis::from_scan_with_ledger` decision, the real shared
//! `score_readiness`, and the real hygiene report's dormant/stale-draft rows.
//! A pure-Rust test cannot cover the half that matters — which rows the
//! grouped query returns, and what an absent key means.
//!
//! **`ChildRunLedger::since` is process-cached** and this binary drives
//! several isolated databases from one process, so every test that seeds rows
//! resets the cache first. That is not a test convenience: it is the same
//! `reset_since_cache` P1 added for exactly this reason.
//!
//! DB tests on the `common` harness (a template clone of the migrated DB per
//! test), so CTRL_TESTS and not TC_TESTS — sub-leg 64b.

mod common;

use chrono::{DateTime, Duration, Utc};
use sqlx::{Pool, Postgres};
use talos_analytics_repository::{
    child_ledger_evidence, score_readiness, AnalyticsRepository, ReadinessBasis,
    ReadinessComponents, CHILD_MEASURABLE_MAX, FULL_MAX, LEDGER_MIN_RUNS,
};
use talos_child_run_ledger::ChildRunLedger;
use uuid::Uuid;

// ── seeds ───────────────────────────────────────────────────────────────────
//
// Named `parent` / `child` rather than after any real workflow: nothing in a
// tracked file should carry a fleet workflow name.

const EMPTY_GRAPH: &str = r#"{"nodes":[],"edges":[]}"#;

/// The shape the ENGINE writes: `type` on the node, the child id under `data`.
fn sub_workflow_graph(child: Uuid) -> String {
    format!(
        r#"{{"nodes":[{{"id":"child","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
    )
}

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'ledger p2')",
    )
    .bind(id)
    .bind(format!("ledger-p2-{id}@example.com"))
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
    status: &str,
    created_days_ago: i64,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled, created_at) \
         VALUES ($1, $2, $3, $4, 'talos://t', $5, true, NOW() - make_interval(days => $6::int))",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(graph)
    .bind(status)
    .bind(i32::try_from(created_days_ago).unwrap())
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// One ledger row, written with the same column set the production writer
/// binds. `status` goes through the DB's own CHECK, so a spelling drift
/// between `ChildDispatchKind::as_str` and the migration fails here.
#[allow(clippy::too_many_arguments)]
async fn seed_child_run(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    parent_wf: Uuid,
    child_wf: Uuid,
    kind: &str,
    status: &str,
    started_at: DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO sub_workflow_runs \
             (parent_execution_id, parent_workflow_id, parent_node_id, dispatch_kind, \
              child_workflow_id, user_id, depth, started_at, completed_at, status, duration_ms) \
         VALUES ($1, $2, 'child', $3, $4, $5, 1, $6, $6 + interval '80 milliseconds', $7, 80)",
    )
    .bind(Uuid::new_v4())
    .bind(parent_wf)
    .bind(kind)
    .bind(child_wf)
    .bind(user_id)
    .bind(started_at)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed child run");
}

/// Serialises every read that touches [`ChildRunLedger::since`].
///
/// The floor cache is PROCESS-WIDE by design — `since()` answers a deployment
/// question, and in production one process talks to one database. This binary
/// drives nine ISOLATED databases from one process and `cargo test` runs them
/// on parallel threads, so without this a test can reset the cache and then
/// read a sibling's floor between its own reset and its own query. Observed:
/// `at_the_floor_the_ledger_restores_the_fleet_scale` passed alone and failed
/// in the full binary.
///
/// This is a TEST-HARNESS fact, not a production one, and it is stated here
/// rather than worked around by weakening an assertion.
static LEDGER_FLOOR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Read ledger evidence with the floor cache held stable for the whole
/// reset→read window.
async fn evidence_for(
    pool: &Pool<Postgres>,
    user: Uuid,
    ids: &[Uuid],
) -> std::collections::HashMap<Uuid, talos_analytics_repository::ChildLedgerEvidence> {
    let _guard = LEDGER_FLOOR_LOCK.lock().await;
    ChildRunLedger::reset_since_cache();
    child_ledger_evidence(pool, user, ids, Utc::now())
        .await
        .expect("ledger evidence")
}

/// Documented, low-risk, and INVISIBLE to `workflow_executions` — the state
/// every child on the reference fleet is in.
fn documented_but_unobserved() -> ReadinessComponents {
    ReadinessComponents {
        reliability: 0.0,
        documentation: 20.0,
        freshness: 0.0,
        risk: 10.0,
    }
}

/// The whole production read path: the real scan, the real batched ledger
/// read, the real basis decision, the real shared scorer.
async fn score_child(
    pool: &Pool<Postgres>,
    repo: &AnalyticsRepository,
    user: Uuid,
    child: Uuid,
) -> talos_analytics_repository::ReadinessOutcome {
    let scan = repo
        .scan_child_parents_for(user, &[child])
        .await
        .expect("child scan");
    let evidence = evidence_for(pool, user, &[child]).await;
    let basis = ReadinessBasis::from_scan_with_ledger(&scan, child, evidence.get(&child).copied());
    // The two execution components come from the ledger EXACTLY as the three
    // production scorers compute them — same `components()`, same shared
    // `compute_*_score` underneath.
    let (reliability, freshness) = match basis.ledger() {
        Some(ev) if basis.max_points() == FULL_MAX && basis.is_parent_dispatched() => {
            ev.components(Utc::now())
        }
        _ => (0.0, 0.0),
    };
    score_readiness(
        ReadinessComponents {
            reliability,
            freshness,
            ..documented_but_unobserved()
        },
        basis,
    )
}

async fn seed_parent_and_child(pool: &Pool<Postgres>, user: Uuid) -> (Uuid, Uuid) {
    let child = seed_workflow(pool, user, "p2-child", EMPTY_GRAPH, "draft", 40).await;
    let parent = seed_workflow(
        pool,
        user,
        "p2-parent",
        &sub_workflow_graph(child),
        "published",
        40,
    )
    .await;
    (parent, child)
}

// ── the floor ───────────────────────────────────────────────────────────────

/// BELOW the floor the child stays on the shrunken denominator, and the
/// SHORTFALL is disclosed with the ledger's own floor beside it. It is never
/// scaled up — #762's second rejected rendering, which would report a
/// documented child as 100/100 on almost no evidence.
///
/// MUTATION that turns it red: `LEDGER_MIN_RUNS = 1`.
#[tokio::test]
async fn below_the_floor_a_child_keeps_the_shrunken_denominator() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let (parent, child) = seed_parent_and_child(&pool, user).await;

    for i in 0..(LEDGER_MIN_RUNS - 1) {
        seed_child_run(
            &pool,
            user,
            parent,
            child,
            "sub_workflow",
            "completed",
            Utc::now() - Duration::hours(i + 1),
        )
        .await;
    }

    let out = score_child(&pool, &repo, user, child).await;
    assert_eq!(
        out.max_points,
        CHILD_MEASURABLE_MAX,
        "{} recorded run(s) is below the {LEDGER_MIN_RUNS}-run floor",
        LEDGER_MIN_RUNS - 1
    );
    assert!(!out.comparable_to_fleet());
    assert_eq!(out.score, 30, "documentation 20 + risk 10, NOT scaled up");
    let note = out.note().expect("a child always carries a note");
    assert!(
        note.contains(&format!(
            "{} child run(s) recorded since",
            LEDGER_MIN_RUNS - 1
        )),
        "the shortfall must be stated with the count: {note}"
    );
    assert!(
        note.contains(&format!("below the {LEDGER_MIN_RUNS}-run floor")),
        "{note}"
    );
}

/// AT the floor the child returns to the 100-point scale, with reliability and
/// freshness MEASURED from `sub_workflow_runs`.
///
/// MUTATION that turns it red: score `LedgerMeasured` on
/// `CHILD_MEASURABLE_MAX`; or make `from_scan_with_ledger` ignore the ledger.
#[tokio::test]
async fn at_the_floor_the_ledger_restores_the_fleet_scale() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());
    let (parent, child) = seed_parent_and_child(&pool, user).await;

    for i in 0..LEDGER_MIN_RUNS {
        seed_child_run(
            &pool,
            user,
            parent,
            child,
            "judge",
            "completed",
            Utc::now() - Duration::hours(i + 1),
        )
        .await;
    }

    let out = score_child(&pool, &repo, user, child).await;
    assert_eq!(out.max_points, FULL_MAX, "back on the fleet scale");
    assert!(out.comparable_to_fleet());
    assert!(out.unmeasured.is_empty());
    assert_eq!(out.basis.as_str(), "ledger");
    // 3 clean runs ⇒ ramp 3/10 × 50 = 15 reliability; a run an hour ago ⇒ 20
    // freshness. Asserted as a NUMBER, not a range: the whole claim is that
    // the two components are computed rather than assumed.
    assert_eq!(
        out.score, 65,
        "20 doc + 10 risk + 15 reliability + 20 freshness"
    );
    assert!(out.basis.is_parent_dispatched(), "still somebody's child");
    assert!(
        !out.basis.is_unmeasurable_child(),
        "…and therefore NOT excluded from below_50_count"
    );
}

/// FAILED ledger runs lower reliability, through the same ramp the fleet uses.
/// The positive control matters here: without it, a mutation that always
/// returned 0 reliability would pass a "failures lower the score" assertion.
///
/// MUTATION that turns it red: compute `success_rate` from `runs` alone.
#[tokio::test]
async fn failed_ledger_runs_lower_reliability() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    let (clean_parent, clean_child) = seed_parent_and_child(&pool, user).await;
    for i in 0..10 {
        seed_child_run(
            &pool,
            user,
            clean_parent,
            clean_child,
            "sub_workflow",
            "completed",
            Utc::now() - Duration::hours(i + 1),
        )
        .await;
    }
    let clean = score_child(&pool, &repo, user, clean_child).await;

    let (bad_parent, bad_child) = seed_parent_and_child(&pool, user).await;
    for i in 0..10 {
        seed_child_run(
            &pool,
            user,
            bad_parent,
            bad_child,
            "sub_workflow",
            if i < 5 { "failed" } else { "completed" },
            Utc::now() - Duration::hours(i + 1),
        )
        .await;
    }
    let half = score_child(&pool, &repo, user, bad_child).await;

    assert_eq!(clean.max_points, FULL_MAX);
    assert_eq!(half.max_points, FULL_MAX);
    // 10 runs saturates the ramp, so reliability is the success rate × 50.
    assert_eq!(clean.score, 100, "20 + 10 + 50 + 20");
    assert_eq!(half.score, 75, "20 + 10 + 25 + 20");
    assert!(clean.score > half.score);
}

/// UNKNOWN is not zero. A run recorded BEFORE the ledger's floor cannot exist
/// (the floor IS the earliest row), so what this pins is the other half: with
/// the floor INSIDE the readiness window, the uncovered part of that window is
/// disclosed as UNKNOWN rather than counted as zero.
///
/// MUTATION that turns it red: drop the coverage clause from
/// `ChildLedgerEvidence::disclosure`, or set `ledger_since` to the window
/// start.
#[tokio::test]
async fn the_part_of_the_window_before_the_floor_is_unknown_not_zero() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let (parent, child) = seed_parent_and_child(&pool, user).await;

    // An EMPTY ledger: the floor is unknown, so a count of 0 says nothing.
    let empty = evidence_for(&pool, user, &[child]).await;
    let ev = empty.get(&child).expect("every id asked about is present");
    assert_eq!(ev.runs, 0);
    assert_eq!(ev.ledger_since, None);
    assert!(
        ev.disclosure().contains("UNKNOWN"),
        "an empty ledger must not render as a measured zero: {}",
        ev.disclosure()
    );

    // The ledger starts recording TODAY, well inside the 30-day window.
    seed_child_run(
        &pool,
        user,
        parent,
        child,
        "sub_workflow",
        "completed",
        Utc::now() - Duration::hours(2),
    )
    .await;
    let partial = evidence_for(&pool, user, &[child]).await;
    let ev = partial.get(&child).expect("present");
    assert_eq!(ev.runs, 1);
    let since = ev.ledger_since.expect("the floor is now known");
    assert!(since > ev.window_start, "the floor is inside the window");
    let d = ev.disclosure();
    assert!(d.contains("UNKNOWN"), "{d}");
    assert!(d.contains("nobody was recording"), "{d}");
}

/// The batched read must be ONE query over `= ANY($1)`, and a child with no
/// rows must be present with an explicit zero-and-a-floor rather than absent —
/// which is what lets the renderer distinguish "recorded none" from "was not
/// asked".
///
/// MUTATION that turns it red: return the raw `child_run_stats_since` map
/// (children with no rows would vanish).
#[tokio::test]
async fn a_child_with_no_recorded_runs_is_present_with_the_floor() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let (parent, busy) = seed_parent_and_child(&pool, user).await;
    let (_, quiet) = seed_parent_and_child(&pool, user).await;

    seed_child_run(
        &pool,
        user,
        parent,
        busy,
        "sub_workflow",
        "completed",
        Utc::now() - Duration::minutes(5),
    )
    .await;

    let map = evidence_for(&pool, user, &[busy, quiet]).await;
    assert_eq!(map.len(), 2, "every id asked about is answered");
    assert_eq!(map[&busy].runs, 1);
    let q = map[&quiet];
    assert_eq!(q.runs, 0);
    assert!(
        q.ledger_since.is_some(),
        "the floor is a DEPLOYMENT fact, so it is known even for a child with no rows"
    );
    let d = q.disclosure();
    assert!(
        d.contains("0 child run(s) recorded since"),
        "with a floor present, a zero here IS a measurement for the covered period: {d}"
    );
    assert!(
        !d.contains("no rows at all"),
        "…and must not be rendered as the empty-ledger UNKNOWN: {d}"
    );
}

/// TENANCY. The ledger read is scoped at the app layer AND under RLS, so
/// another user's child runs must not raise this user's reliability.
#[tokio::test]
async fn another_users_child_runs_are_not_visible() {
    let (pool, _db) = common::isolated_db_pool().await;
    let mine = seed_user(&pool).await;
    let theirs = seed_user(&pool).await;
    let (parent, child) = seed_parent_and_child(&pool, mine).await;

    // Rows for the SAME child workflow id, attributed to another user. The
    // ledger has no FK on `child_workflow_id`, so this is a shape the table
    // genuinely admits.
    for i in 0..10 {
        seed_child_run(
            &pool,
            theirs,
            parent,
            child,
            "sub_workflow",
            "completed",
            Utc::now() - Duration::hours(i + 1),
        )
        .await;
    }

    let map = evidence_for(&pool, mine, &[child]).await;
    assert_eq!(
        map[&child].runs, 0,
        "another tenant's rows must not count toward this child's reliability"
    );
}

/// EVERY dispatch kind the enum names must satisfy the table's widened CHECK
/// (RFC 0012 P2's four additions included). A spelling drift between
/// `ChildDispatchKind::as_str` and the migration is invisible to `cargo check`
/// and shows up as a failed INSERT at runtime, where the recorder swallows it.
#[tokio::test]
async fn every_dispatch_kind_spelling_satisfies_the_widened_check() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let (parent, child) = seed_parent_and_child(&pool, user).await;

    let kinds = talos_workflow_engine_core::ChildDispatchKind::ALL;
    assert_eq!(kinds.len(), 9, "RFC 0012 P2 records nine dispatch kinds");
    for kind in kinds {
        seed_child_run(
            &pool,
            user,
            parent,
            child,
            kind.as_str(),
            "completed",
            Utc::now() - Duration::minutes(1),
        )
        .await;
    }

    let map = evidence_for(&pool, user, &[child]).await;
    assert_eq!(
        map[&child].runs,
        i64::try_from(kinds.len()).unwrap(),
        "every spelling landed a row"
    );
}

// ── the below_50 exclusion, and the hygiene rows ────────────────────────────

/// The `below_50_count` exclusion must follow the BASIS, not child-ness.
///
/// #762 excluded every child because a child was ≤30 by construction. Once the
/// ledger can measure one, that reasoning stops applying to it: a
/// ledger-measured child scoring 47 is a REAL below-50 finding, and excluding
/// it would hide the platform's most-used sub-workflows from the one count
/// that would notice them degrading.
///
/// MUTATION that turns it red: make `is_unmeasurable_child` an alias of
/// `is_parent_dispatched` (the pre-P2 predicate).
#[tokio::test]
async fn the_below_50_exclusion_follows_the_basis() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    // A child the ledger cannot measure: below the floor.
    let (thin_parent, thin) = seed_parent_and_child(&pool, user).await;
    seed_child_run(
        &pool,
        user,
        thin_parent,
        thin,
        "sub_workflow",
        "completed",
        Utc::now() - Duration::hours(1),
    )
    .await;

    // A child the ledger CAN measure, and which is genuinely unreliable — the
    // shape the old blanket exclusion would hide.
    let (bad_parent, bad) = seed_parent_and_child(&pool, user).await;
    for i in 0..10 {
        seed_child_run(
            &pool,
            user,
            bad_parent,
            bad,
            "sub_workflow",
            "failed",
            Utc::now() - Duration::hours(i + 1),
        )
        .await;
    }

    let scan = repo
        .scan_child_parents_for(user, &[thin, bad])
        .await
        .expect("scan");
    let ev = evidence_for(&pool, user, &[thin, bad]).await;

    let thin_basis = ReadinessBasis::from_scan_with_ledger(&scan, thin, ev.get(&thin).copied());
    let bad_basis = ReadinessBasis::from_scan_with_ledger(&scan, bad, ev.get(&bad).copied());

    assert!(
        thin_basis.is_unmeasurable_child(),
        "below the floor ⇒ 30-point basis ⇒ excluded from below_50_count"
    );
    assert!(
        !bad_basis.is_unmeasurable_child(),
        "ledger-measured ⇒ fleet scale ⇒ NOT excluded"
    );
    assert_eq!(thin_basis.max_points(), CHILD_MEASURABLE_MAX);
    assert_eq!(bad_basis.max_points(), FULL_MAX);

    // …and the ledger-measured one really is below 50, so the exclusion change
    // is not academic: 20 doc + 10 risk + 0 reliability (every run failed) +
    // 20 freshness = 50 - reliability. Assert the number rather than a range.
    let scored = score_child(&pool, &repo, user, bad).await;
    assert_eq!(scored.score, 50, "20 + 10 + 0 reliability + 20 freshness");
}

/// The HYGIENE rows read the ledger, and `last_child_run_at` replaces the
/// `execution_cost_rollup` proxy as the answer to "did this child run?".
///
/// The proxy is kept BENEATH it and demoted — measured 2026-09-07, its worst
/// case on the reference deployment is 0% recall over a 30-day window — but a
/// proxy that can speak for the period before the ledger's first row is not
/// nothing, so it is retained and captioned rather than deleted.
///
/// MUTATION that turns it red: drop the `child_runs` stamp at the join site
/// (the row would carry the proxy alone, i.e. the pre-P2 answer).
#[tokio::test]
async fn the_hygiene_rows_carry_the_ledgers_answer() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = AnalyticsRepository::new(pool.clone());

    // A DORMANT child: created 40 days ago, no execution row, dispatched by an
    // enabled parent — the exact shape #758 found under a delete instruction.
    let (parent, child) = seed_parent_and_child(&pool, user).await;
    seed_child_run(
        &pool,
        user,
        parent,
        child,
        "sub_workflow",
        "completed",
        Utc::now() - Duration::hours(3),
    )
    .await;

    // The report reads the ledger INTERNALLY, so the floor cache must be held
    // stable across the whole call rather than around a read of our own.
    let report = {
        let _guard = LEDGER_FLOOR_LOCK.lock().await;
        ChildRunLedger::reset_since_cache();
        repo.get_hygiene_report(user).await.expect("hygiene report")
    };

    let dormant = report
        .dormant_workflows
        .iter()
        .find(|r| r.id == child)
        .expect("the child is listed as dormant — it has no workflow_executions row");
    assert_eq!(dormant.last_execution, None, "and it never will have one");
    let ev = dormant
        .child_runs
        .as_ref()
        .expect("the ledger was read for this row");
    assert_eq!(ev.runs, 1);
    assert!(
        ev.last_run_at.is_some(),
        "the RUN is timestamped, not a fuel row"
    );
    assert!(ev.ledger_since.is_some());
    assert!(
        ev.note().contains("This workflow RUNS"),
        "the note must refute the list's own premise: {}",
        ev.note()
    );
    // The proxy is the thing being superseded and is legitimately NULL here —
    // which is the whole point: it has 0% recall on this shape.
    assert_eq!(dormant.last_child_activity_at, None);

    // The STALE-DRAFT list is the destructive one, and the ledger answers its
    // premise ("never executed") directly.
    let draft = report
        .stale_draft_workflows
        .iter()
        .find(|r| r.id == child)
        .expect("the child is a draft created 40 days ago with no execution row");
    let ev = draft
        .child_runs
        .as_ref()
        .expect("the ledger was read for this row too");
    assert_eq!(ev.runs, 1);
}
