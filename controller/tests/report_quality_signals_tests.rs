//! Weekly self-report quality signals — teacher-audit ceilings +
//! observe-only judge scores.
//!
//! Covers the two new repository queries added for the `assistant_report`
//! node: `ExecutionRepository::{record_judge_score, weekly_judge_scores}`
//! (the judge-score insert + per-(workflow, judge node) aggregate) and
//! `talos_ml::teacher_ceilings` (per-model teacher-audit ceiling read).
//! Each runs against an isolated `CREATE DATABASE … TEMPLATE` clone so
//! the binaries parallelise without shared-state cleanup.

mod common;

use talos_execution_repository::ExecutionRepository;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_workflow(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid, user_id: Uuid, name: &str) {
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'talos://test', '{}')",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed workflow");
}

// ── Judge scores ───────────────────────────────────────────────────────

#[tokio::test]
async fn judge_scores_insert_and_weekly_aggregate() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let node = Uuid::new_v4();
    let exec = Uuid::new_v4();
    seed_user(&pool, user, "judge@quality.test").await;
    seed_workflow(&pool, wf, user, "pa-daily-brief").await;

    // Three verdicts on the same workflow: 0.9 pass, 0.4 fail, 0.6 pass.
    for (score, passed) in [(0.9_f64, true), (0.4, false), (0.6, true)] {
        let mut conn = pool.acquire().await.expect("acquire");
        ExecutionRepository::record_judge_score(&mut conn, wf, node, exec, score, passed, false)
            .await
            .expect("insert judge score");
    }

    let stats = repo
        .weekly_judge_scores(user, 7)
        .await
        .expect("weekly judge scores");
    assert_eq!(stats.len(), 1, "one judged workflow");
    let s = &stats[0];
    assert_eq!(s.workflow_name, "pa-daily-brief");
    assert_eq!(s.runs, 3);
    let avg = s.avg_score.expect("avg present");
    assert!((avg - 0.6333).abs() < 1e-3, "avg ~0.633, got {avg}");
    let pass_rate = s.pass_rate.expect("pass_rate present");
    assert!(
        (pass_rate - 0.6667).abs() < 1e-3,
        "2/3 passed, got {pass_rate}"
    );
    assert_eq!(s.worst_score, Some(0.4), "min score");
    assert_eq!(s.na_runs, 0, "nothing abstained");
}

/// Abstentions are RECORDED but excluded from every quality aggregate.
///
/// The three verdicts above (0.9 pass, 0.4 fail, 0.6 pass) are joined by two
/// abstentions carrying a 1.0/pass payload — the shape a real abstaining
/// judge writes so an empty run doesn't fail the workflow. If they leaked
/// into the aggregates, avg would rise 0.633 → 0.78, pass_rate 0.667 → 0.8,
/// and `runs` would read 5: exactly the inflation this change exists to
/// prevent. Every number below must be IDENTICAL to the all-scored case,
/// with the abstentions visible only as `na_runs`.
#[tokio::test]
async fn weekly_judge_scores_excludes_abstentions_but_counts_them() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let node = Uuid::new_v4();
    let exec = Uuid::new_v4();
    seed_user(&pool, user, "abstain@quality.test").await;
    seed_workflow(&pool, wf, user, "pa-inbox-organizer").await;

    for (score, passed, na) in [
        (0.9_f64, true, false),
        (0.4, false, false),
        (0.6, true, false),
        // Two abstentions with a perfect-score payload — the poison case.
        (1.0, true, true),
        (1.0, true, true),
    ] {
        let mut conn = pool.acquire().await.expect("acquire");
        ExecutionRepository::record_judge_score(&mut conn, wf, node, exec, score, passed, na)
            .await
            .expect("insert judge score");
    }

    // All five rows really are on disk — the abstentions were recorded, not
    // dropped. (Dropping them is what destroyed the abstention rate before.)
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM judge_scores WHERE workflow_id = $1")
        .bind(wf)
        .fetch_one(&pool)
        .await
        .expect("count rows");
    assert_eq!(total, 5, "abstentions must be persisted, not skipped");

    let stats = repo.weekly_judge_scores(user, 7).await.expect("stats");
    assert_eq!(stats.len(), 1);
    let s = &stats[0];
    assert_eq!(s.runs, 3, "runs counts SCORED verdicts only");
    assert_eq!(s.na_runs, 2, "abstentions are counted separately");

    let avg = s.avg_score.expect("avg present");
    assert!(
        (avg - 0.6333).abs() < 1e-3,
        "avg must ignore the 1.0 abstentions (0.633, not 0.78); got {avg}"
    );
    let pass_rate = s.pass_rate.expect("pass_rate present");
    assert!(
        (pass_rate - 0.6667).abs() < 1e-3,
        "pass_rate denominator is scored runs (2/3, not 4/5); got {pass_rate}"
    );
    assert_eq!(
        s.worst_score,
        Some(0.4),
        "worst is the worst SCORED verdict"
    );
}

/// A judge that abstained on EVERY run still appears — with `runs = 0` and
/// NULL aggregates. Reporting nothing would hide a judge that fired 4 times
/// and measured nothing; inventing a score for it would be worse.
#[tokio::test]
async fn weekly_judge_scores_all_abstentions_reports_zero_scored_runs() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    seed_user(&pool, user, "allna@quality.test").await;
    seed_workflow(&pool, wf, user, "pa-quiet-inbox").await;

    // ONE judge, abstaining four times. The node id is now a grouping key
    // (2026-07-29), so it must be held fixed — a fresh uuid per insert would
    // describe four different judges that abstained once each.
    let node = Uuid::new_v4();
    for _ in 0..4 {
        let mut conn = pool.acquire().await.expect("acquire");
        ExecutionRepository::record_judge_score(
            &mut conn,
            wf,
            node,
            Uuid::new_v4(),
            1.0,
            true,
            true,
        )
        .await
        .expect("insert");
    }

    let stats = repo.weekly_judge_scores(user, 7).await.expect("stats");
    assert_eq!(stats.len(), 1, "an all-abstaining judge is still reported");
    let s = &stats[0];
    assert_eq!(s.runs, 0);
    assert_eq!(s.na_runs, 4);
    assert_eq!(s.avg_score, None, "no scored verdict to average");
    assert_eq!(s.pass_rate, None, "no scored denominator");
    assert_eq!(s.worst_score, None);
}

/// The column defaults to `false`, so a row written WITHOUT the flag (the
/// pre-migration shape) still counts as scored — the no-backfill decision.
#[tokio::test]
async fn judge_scores_not_applicable_defaults_false_for_legacy_shaped_rows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    seed_user(&pool, user, "legacy@quality.test").await;
    seed_workflow(&pool, wf, user, "legacy-judge").await;

    // Insert exactly as the pre-migration writer did — no not_applicable.
    sqlx::query(
        "INSERT INTO judge_scores (workflow_id, node_id, execution_id, score, passed) \
         VALUES ($1, $2, $3, 0.5, true)",
    )
    .bind(wf)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("legacy insert");

    let stats = repo.weekly_judge_scores(user, 7).await.expect("stats");
    let s = &stats[0];
    assert_eq!(s.runs, 1, "a legacy row is a SCORED row");
    assert_eq!(s.na_runs, 0);
    assert_eq!(s.avg_score, Some(0.5));
}

#[tokio::test]
async fn weekly_judge_scores_is_tenant_scoped() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let wf_b = Uuid::new_v4();
    seed_user(&pool, user_a, "a@quality.test").await;
    seed_user(&pool, user_b, "b@quality.test").await;
    seed_workflow(&pool, wf_b, user_b, "b-workflow").await;

    let mut conn = pool.acquire().await.expect("acquire");
    ExecutionRepository::record_judge_score(
        &mut conn,
        wf_b,
        Uuid::new_v4(),
        Uuid::new_v4(),
        0.5,
        true,
        false,
    )
    .await
    .expect("insert");

    // User A owns no judged workflow → empty (never sees user B's rows).
    let a_stats = repo.weekly_judge_scores(user_a, 7).await.expect("a stats");
    assert!(
        a_stats.is_empty(),
        "user A must not see user B's judge scores"
    );
    let b_stats = repo.weekly_judge_scores(user_b, 7).await.expect("b stats");
    assert_eq!(b_stats.len(), 1);
}

/// D4 (2026-07-29): the aggregate's grain is `(workflow, judge NODE)`.
///
/// Both inbox organizers run TWO judges — a rubric `judge` and a structural
/// `coverage_judge`. Grouping by workflow name alone pooled them into one
/// trend, so a saturated shape-check that never fails hid inside a
/// discriminating rubric's spread and the digest's `saturated_pass` flag
/// could never fire for it. Dropping `node_id` from the GROUP BY collapses
/// these two rows back into one and fails here.
#[tokio::test]
async fn weekly_judge_scores_are_per_judge_not_per_workflow() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let rubric_judge = Uuid::new_v4();
    let coverage_judge = Uuid::new_v4();
    seed_user(&pool, user, "twojudges@quality.test").await;
    seed_workflow(&pool, wf, user, "pa-inbox-organizer-work").await;

    // The rubric judge discriminates: 0.9 pass, 0.3 fail, plus an abstention.
    // The coverage judge is saturated: 1.0 pass, twice.
    let rows: [(Uuid, f64, bool, bool); 5] = [
        (rubric_judge, 0.9, true, false),
        (rubric_judge, 0.3, false, false),
        (rubric_judge, 1.0, true, true),
        (coverage_judge, 1.0, true, false),
        (coverage_judge, 1.0, true, false),
    ];
    for (node, score, passed, na) in rows {
        let mut conn = pool.acquire().await.expect("acquire");
        ExecutionRepository::record_judge_score(
            &mut conn,
            wf,
            node,
            Uuid::new_v4(),
            score,
            passed,
            na,
        )
        .await
        .expect("insert judge score");
    }

    let stats = repo.weekly_judge_scores(user, 7).await.expect("stats");
    assert_eq!(stats.len(), 2, "one row PER JUDGE, not per workflow");
    for s in &stats {
        assert_eq!(s.workflow_name, "pa-inbox-organizer-work");
        assert_eq!(s.workflow_id, wf, "the row must carry its workflow id");
    }

    let rubric = stats
        .iter()
        .find(|s| s.node_id == rubric_judge)
        .expect("rubric judge row");
    let coverage = stats
        .iter()
        .find(|s| s.node_id == coverage_judge)
        .expect("coverage judge row");

    // FILTER semantics hold PER ROW: the abstention is excluded from the
    // rubric judge's aggregates and counted only in its own `na_runs`.
    assert_eq!(rubric.runs, 2, "scored verdicts only");
    assert_eq!(rubric.na_runs, 1, "abstention counted on ITS judge");
    assert_eq!(rubric.worst_score, Some(0.3));
    assert!((rubric.avg_score.expect("avg") - 0.6).abs() < 1e-9);
    assert!((rubric.pass_rate.expect("rate") - 0.5).abs() < 1e-9);

    // The saturated judge is now visible AS saturated — pooled with the
    // rubric judge its spread would have been 0.3..1.0 and read as healthy.
    assert_eq!(coverage.runs, 2);
    assert_eq!(
        coverage.na_runs, 0,
        "abstentions do not bleed across judges"
    );
    assert_eq!(coverage.avg_score, Some(1.0));
    assert_eq!(coverage.worst_score, Some(1.0));
    // Zero spread — `avg == worst` is the exact test `judge_signal` applies.
    // Pooled with the rubric judge the spread would have been 0.3..1.0 and
    // read as healthy, so this row could never have been flagged.
    assert_eq!(
        coverage.avg_score, coverage.worst_score,
        "the saturated judge's spread is only visible on its OWN row"
    );
    assert_ne!(
        rubric.avg_score, rubric.worst_score,
        "the rubric judge genuinely varies"
    );

    // ── 2026-08-19: the per-verdict-group spread, straight from SQL ──────
    //
    // These five columns are the ONLY basis for the `mirrors_pass` /
    // `constant_score` / `score_out_of_domain` signals, and the unit tests
    // in `talos-operator-digest` build the struct by hand — so nothing else
    // in the suite would notice a mistyped `FILTER` clause or a renamed
    // column. `try_get` makes drift loud rather than silent (check 52), but
    // a WRONG-BUT-VALID predicate reads as perfectly healthy data, which is
    // exactly the class this change exists to close. Assert the values.
    assert_eq!(rubric.scored_passed, 1, "one scored pass (0.9)");
    assert_eq!(rubric.scored_failed(), 1, "one scored fail (0.3)");
    assert_eq!(rubric.pass_score_min, Some(0.9));
    assert_eq!(rubric.pass_score_max, Some(0.9));
    assert_eq!(rubric.fail_score_min, Some(0.3));
    assert_eq!(rubric.fail_score_max, Some(0.3));
    assert_eq!(rubric.best_score(), Some(0.9));
    // The ABSTENTION (score 1.0, passed=true) must not leak into the passing
    // group — if it did, `pass_score_max` would read 1.0 and the mirror test
    // would silently stop holding. This is the `FILTER (WHERE NOT
    // not_applicable)` guarantee asserted at the group grain for the first
    // time.
    assert_ne!(
        rubric.pass_score_max,
        Some(1.0),
        "the abstention must be excluded from the passing group too"
    );
    // Two constants, one per verdict ⇒ this judge's score is a re-encoding
    // of `passed`, and the digest must say so instead of calling its spread
    // a meaningful trend.
    assert!(
        rubric.score_mirrors_passed(),
        "0.9 on every pass and 0.3 on every fail is a verdict mirror"
    );

    // The all-passing judge has an EMPTY failing group, so no mirror can be
    // claimed: the failure branch was never exercised. It stays saturated.
    assert_eq!(coverage.scored_passed, 2);
    assert_eq!(coverage.scored_failed(), 0);
    assert_eq!(
        coverage.fail_score_min, None,
        "no failing verdicts to bound"
    );
    assert_eq!(coverage.fail_score_max, None);
    assert!(
        !coverage.score_mirrors_passed(),
        "an unexercised failure branch is not evidence of a mirror"
    );
}

/// Two DIFFERENT workflows that share a name are also no longer pooled —
/// the old `GROUP BY w.name` merged them into one trend.
#[tokio::test]
async fn weekly_judge_scores_do_not_pool_same_named_workflows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());

    let user = Uuid::new_v4();
    let wf_a = Uuid::new_v4();
    let wf_b = Uuid::new_v4();
    seed_user(&pool, user, "samename@quality.test").await;
    seed_workflow(&pool, wf_a, user, "pa-recall").await;
    seed_workflow(&pool, wf_b, user, "pa-recall").await;

    for wf in [wf_a, wf_b] {
        let mut conn = pool.acquire().await.expect("acquire");
        ExecutionRepository::record_judge_score(
            &mut conn,
            wf,
            Uuid::new_v4(),
            Uuid::new_v4(),
            0.5,
            true,
            false,
        )
        .await
        .expect("insert");
    }

    let stats = repo.weekly_judge_scores(user, 7).await.expect("stats");
    assert_eq!(stats.len(), 2, "same name, different workflows, two rows");
    let mut ids: Vec<Uuid> = stats.iter().map(|s| s.workflow_id).collect();
    ids.sort();
    let mut expected = vec![wf_a, wf_b];
    expected.sort();
    assert_eq!(ids, expected);
}

#[tokio::test]
async fn weekly_judge_scores_empty_when_no_rows() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());
    let user = Uuid::new_v4();
    seed_user(&pool, user, "empty@quality.test").await;
    // Degrades gracefully — no judged workflow → empty section.
    let stats = repo.weekly_judge_scores(user, 7).await.expect("stats");
    assert!(stats.is_empty());
}

// ── Teacher-audit ceilings ─────────────────────────────────────────────

#[tokio::test]
async fn teacher_ceilings_surfaces_completed_audit() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user, "teacher@quality.test").await;

    let model = Uuid::new_v4();
    let audit = serde_json::json!({
        "status": "complete",
        "audited_at": "2026-07-20T12:00:00Z",
        "compared": 100,
        "agree": 82,
        "parse_failed": 3,
        "accuracy": 0.82,
        "per_class": { "archive": {"n": 40, "agree": 35}, "follow_up": {"n": 60, "agree": 47} },
        "mismatches": [{"human": "archive", "teacher": "follow_up"}],
    });
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, config_json, teacher_audit) \
         VALUES ($1, $2, 'inbox-classifier', 'classification', '{}'::jsonb, $3)",
    )
    .bind(model)
    .bind(user)
    .bind(&audit)
    .execute(&pool)
    .await
    .expect("seed model with audit");

    let out = talos_ml::teacher_ceilings(&pool, user)
        .await
        .expect("teacher ceilings");
    let models = out["models"].as_array().expect("models array");
    assert_eq!(models.len(), 1);
    let m = &models[0];
    assert_eq!(m["name"], "inbox-classifier");
    assert_eq!(m["status"], "complete");
    assert_eq!(m["ceiling_accuracy"], 0.82);
    assert_eq!(m["parse_failed"], 3);
    assert_eq!(m["compared"], 100);
    assert_eq!(m["per_class"]["archive"]["agree"], 35);
    assert_eq!(m["audited_at"], "2026-07-20T12:00:00Z");
    // DLP: raw disagreement mismatches are NOT surfaced in the report.
    assert!(m.get("mismatches").is_none());
    assert_eq!(out["trend_available"], false);
}

#[tokio::test]
async fn teacher_ceilings_empty_when_unaudited() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user, "unaudited@quality.test").await;
    // A model with NULL teacher_audit is excluded → graceful empty section.
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, config_json) \
         VALUES ($1, $2, 'fresh-model', 'classification', '{}'::jsonb)",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed model");

    let out = talos_ml::teacher_ceilings(&pool, user)
        .await
        .expect("teacher ceilings");
    assert!(out["models"].as_array().expect("array").is_empty());
    assert_eq!(out["trend_available"], false);
}

// ── Memory-rank outcome labels: the "newest verdict" lateral ────────────
//
// `talos_memory::fetch_rank_training_examples` labels each memory-provenance
// row with its execution's newest judge verdict. An ABSTENTION is not an
// outcome label — the run had nothing to judge — so the lateral must skip it
// and fall through to the prior SCORED verdict. Without that, an abstaining
// judge silently relabels the training data for the learned ranker with a
// verdict about nothing.

async fn seed_memory_provenance(
    pool: &sqlx::Pool<sqlx::Postgres>,
    exec: Uuid,
    actor: Uuid,
    key: &str,
) {
    sqlx::query(
        "INSERT INTO execution_memory_context \
             (execution_id, actor_id, memory_key, relevance, recency, importance, \
              fused_score, rank) \
         VALUES ($1, $2, $3, 0.5, 0.5, 0.5, 0.5, 0)",
    )
    .bind(exec)
    .bind(actor)
    .bind(key)
    .execute(pool)
    .await
    .expect("seed provenance");
}

/// Newest verdict is an ABSTENTION → the prior SCORED verdict is the label.
#[tokio::test]
async fn rank_training_label_skips_abstention_and_uses_prior_scored_verdict() {
    let (pool, _db) = common::isolated_db_pool().await;

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let exec = Uuid::new_v4();
    seed_user(&pool, user, "rank@quality.test").await;
    seed_workflow(&pool, wf, user, "rank-wf").await;
    seed_memory_provenance(&pool, exec, actor, "mem/a").await;

    // A real scored verdict, THEN a later abstention on the same execution.
    // `created_at` defaults to now(), so insert order fixes the ordering.
    let mut conn = pool.acquire().await.expect("acquire");
    ExecutionRepository::record_judge_score(
        &mut conn,
        wf,
        Uuid::new_v4(),
        exec,
        0.35,
        false,
        false,
    )
    .await
    .expect("scored verdict");
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 1.0, true, true)
        .await
        .expect("abstention");

    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let rows = talos_memory::fetch_rank_training_examples(&pool, actor, since, 50)
        .await
        .expect("training examples");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].judge_score,
        Some(0.35),
        "the abstention must not become the outcome label — the prior scored \
         verdict is the newest real one"
    );
    assert_eq!(rows[0].judge_passed, Some(false));
}

/// The execution's ONLY verdict is an abstention → no label at all. `None` is
/// the honest answer; inventing a pass from a verdict about nothing would
/// poison the ranker's training data.
#[tokio::test]
async fn rank_training_label_is_none_when_every_verdict_abstained() {
    let (pool, _db) = common::isolated_db_pool().await;

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let exec = Uuid::new_v4();
    seed_user(&pool, user, "allna-rank@quality.test").await;
    seed_workflow(&pool, wf, user, "rank-wf-na").await;
    seed_memory_provenance(&pool, exec, actor, "mem/b").await;

    let mut conn = pool.acquire().await.expect("acquire");
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 1.0, true, true)
        .await
        .expect("abstention");

    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let rows = talos_memory::fetch_rank_training_examples(&pool, actor, since, 50)
        .await
        .expect("training examples");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].judge_score, None);
    assert_eq!(rows[0].judge_passed, None);
}

/// The observational-eval source (`fetch_execution_memory_outcomes`) applies
/// the same rule — an all-abstaining execution arrives UNLABELED, which is
/// what makes `analyze_observational` drop it from the correlation.
#[tokio::test]
async fn execution_memory_outcomes_leave_all_abstaining_executions_unlabeled() {
    let (pool, _db) = common::isolated_db_pool().await;

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let exec = Uuid::new_v4();
    seed_user(&pool, user, "obs-na@quality.test").await;
    seed_workflow(&pool, wf, user, "obs-wf-na").await;
    seed_memory_provenance(&pool, exec, actor, "mem/c").await;

    let mut conn = pool.acquire().await.expect("acquire");
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 1.0, true, true)
        .await
        .expect("abstention");

    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let rows = talos_memory::fetch_execution_memory_outcomes(&pool, actor, since, 50)
        .await
        .expect("outcomes");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].judge_passed, None,
        "an abstention is not an outcome label"
    );
    assert_eq!(rows[0].judge_score, None);
}

// ── Multi-judge outcome labels: unanimity, not write order ──────────────
//
// A workflow can run several judges (the organizers pair an in-path shape
// `judge` with a leaf `coverage_judge`; pa-chief-of-staff pairs an inline
// `judge` with an LLM `quality_judge`). The label lateral used to take the
// NEWEST verdict, and each verdict is recorded by its own fire-and-forget
// `tokio::spawn`, so `created_at` ordered the DB round-trips rather than the
// graph — measured on the live table, two runs of the identical
// pa-chief-of-staff graph landed their two verdicts 10 µs apart in OPPOSITE
// orders. These tests pin the replacement rule: unanimity, order-free.
//
// Every one of them FAILS under `ORDER BY created_at DESC LIMIT 1`.

/// Two judges DISAGREE on `passed` → no label at all, and `judge_disputed`
/// says why. Under the old rule the label was whichever verdict was written
/// last; here the second insert passes, so the old rule produced
/// `Some(true)` — asserting the half of a contradiction that happened to
/// win a race.
#[tokio::test]
async fn disputed_verdicts_yield_no_label_and_are_flagged() {
    let (pool, _db) = common::isolated_db_pool().await;

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let exec = Uuid::new_v4();
    seed_user(&pool, user, "disputed@quality.test").await;
    seed_workflow(&pool, wf, user, "disputed-wf").await;
    seed_memory_provenance(&pool, exec, actor, "mem/dispute").await;

    let mut conn = pool.acquire().await.expect("acquire");
    // Shape judge fails the run; the leaf coverage judge passes it.
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 0.2, false, false)
        .await
        .expect("shape verdict");
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 1.0, true, false)
        .await
        .expect("coverage verdict");

    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let rows = talos_memory::fetch_rank_training_examples(&pool, actor, since, 50)
        .await
        .expect("training examples");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].judge_passed, None,
        "the judges contradicted each other — asserting either half would be \
         a label the data does not support"
    );
    assert_eq!(rows[0].judge_score, None);
    assert!(
        rows[0].judge_disputed,
        "a withdrawn label must be distinguishable from an absent judge"
    );

    let outcomes = talos_memory::fetch_execution_memory_outcomes(&pool, actor, since, 50)
        .await
        .expect("outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].judge_passed, None);
    assert!(outcomes[0].judge_disputed);
}

/// Judges AGREE on `passed` but score differently → the label survives and
/// carries the WORST score. This is the live pa-chief-of-staff shape: an
/// inline `judge` at 1.0 beside an LLM `quality_judge` at 0.85. Under the old
/// rule the answer was whichever landed last (measured: the optimistic 1.0 in
/// 5 of the 6 live cases).
#[tokio::test]
async fn agreeing_judges_label_with_the_worst_score_not_the_newest() {
    let (pool, _db) = common::isolated_db_pool().await;

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let exec = Uuid::new_v4();
    seed_user(&pool, user, "agree@quality.test").await;
    seed_workflow(&pool, wf, user, "agree-wf").await;
    seed_memory_provenance(&pool, exec, actor, "mem/agree").await;

    let mut conn = pool.acquire().await.expect("acquire");
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 0.85, true, false)
        .await
        .expect("rubric verdict");
    // Written LAST, and the optimistic one — the old rule would return 1.0.
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 1.0, true, false)
        .await
        .expect("shape verdict");

    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let rows = talos_memory::fetch_rank_training_examples(&pool, actor, since, 50)
        .await
        .expect("training examples");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].judge_passed, Some(true));
    assert_eq!(
        rows[0].judge_score,
        Some(0.85),
        "the label is the worst score among judges that agreed, not the one \
         whose insert happened to land last"
    );
    assert!(!rows[0].judge_disputed);
}

/// The rule must be ORDER-FREE: the same two verdicts written in the opposite
/// order must produce the identical label. This is the property that makes a
/// judge added tomorrow unable to become the teacher by being written last.
#[tokio::test]
async fn the_label_does_not_depend_on_which_verdict_was_written_first() {
    let (pool, _db) = common::isolated_db_pool().await;

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let exec_a = Uuid::new_v4();
    let exec_b = Uuid::new_v4();
    seed_user(&pool, user, "orderfree@quality.test").await;
    seed_workflow(&pool, wf, user, "orderfree-wf").await;
    seed_memory_provenance(&pool, exec_a, actor, "mem/order-a").await;
    seed_memory_provenance(&pool, exec_b, actor, "mem/order-b").await;

    let mut conn = pool.acquire().await.expect("acquire");
    // exec_a: 0.9 then 0.4.  exec_b: 0.4 then 0.9.  Same multiset.
    for (exec, first, second) in [(exec_a, 0.9_f64, 0.4_f64), (exec_b, 0.4, 0.9)] {
        ExecutionRepository::record_judge_score(
            &mut conn,
            wf,
            Uuid::new_v4(),
            exec,
            first,
            true,
            false,
        )
        .await
        .expect("first verdict");
        ExecutionRepository::record_judge_score(
            &mut conn,
            wf,
            Uuid::new_v4(),
            exec,
            second,
            true,
            false,
        )
        .await
        .expect("second verdict");
    }

    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let outcomes = talos_memory::fetch_execution_memory_outcomes(&pool, actor, since, 50)
        .await
        .expect("outcomes");
    assert_eq!(outcomes.len(), 2);
    let a = outcomes
        .iter()
        .find(|o| o.execution_id == exec_a)
        .expect("exec_a");
    let b = outcomes
        .iter()
        .find(|o| o.execution_id == exec_b)
        .expect("exec_b");
    assert_eq!(
        a.judge_score, b.judge_score,
        "two executions carrying the same verdicts in opposite write order \
         must receive the same label"
    );
    assert_eq!(a.judge_score, Some(0.4));
}

/// An ABSTENTION alongside a real verdict must neither dispute it nor drag
/// the score: abstentions are excluded before unanimity is evaluated, so a
/// judge saying "nothing to judge" cannot withdraw another judge's label.
/// (The organizers' `coverage_judge` abstains on an empty inbox 36 times in
/// the live table while the in-path `judge` still scores — this is that case.)
#[tokio::test]
async fn an_abstention_neither_disputes_nor_drags_a_real_verdict() {
    let (pool, _db) = common::isolated_db_pool().await;

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let exec = Uuid::new_v4();
    seed_user(&pool, user, "abstain-mix@quality.test").await;
    seed_workflow(&pool, wf, user, "abstain-mix-wf").await;
    seed_memory_provenance(&pool, exec, actor, "mem/abstain-mix").await;

    let mut conn = pool.acquire().await.expect("acquire");
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 0.7, true, false)
        .await
        .expect("scored verdict");
    // An abstention authored with the opposite `passed` and a lower score:
    // if abstentions were not excluded first, this would both dispute the
    // label and drop the score to 0.0.
    ExecutionRepository::record_judge_score(&mut conn, wf, Uuid::new_v4(), exec, 0.0, false, true)
        .await
        .expect("abstention");

    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let rows = talos_memory::fetch_rank_training_examples(&pool, actor, since, 50)
        .await
        .expect("training examples");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].judge_passed, Some(true));
    assert_eq!(rows[0].judge_score, Some(0.7));
    assert!(!rows[0].judge_disputed);
}

// ── Auth-failure risk signal: the empty set ────────────────────────────
//
// `AnalyticsRepository::count_recent_auth_failures` backs the
// `repeated_auth_failures` field of `get_workflow_risk_assessment`. Its
// query is an UNGROUPED aggregate over `workflow_executions`, and until
// 2026-08-31 it decoded `MAX(started_at)` into a non-`Option` `String`.
// An aggregate over nothing is NULL, not 0 — so the query FAILED with
// "unexpected null; try decoding as an Option" in exactly the case that
// is overwhelmingly common and overwhelmingly good news: a workflow with
// no auth failures. Measured on the live DB the day of the fix: 30 of 30
// workflows took the broken branch.
//
// The bug was invisible for as long as the error was swallowed into `0`,
// because `0` was the correct answer — right output, broken query. #704
// made report handlers disclose a failed read instead of defaulting it,
// which converted the latent break into a `report_field_not_measured`
// disclosure on nearly every call.
//
// These tests exist because the empty-set case was the one case never
// tested. They need a real Postgres: the defect IS the decode of a real
// NULL from a real ungrouped aggregate, which no mock reproduces.

#[tokio::test]
async fn auth_failure_count_over_an_empty_window_is_zero_not_a_decode_error() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = talos_analytics_repository::AnalyticsRepository::new(pool.clone());

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    seed_user(&pool, user, "authfail-empty@quality.test").await;
    seed_workflow(&pool, wf, user, "pa-no-auth-failures").await;

    // A real workflow with ZERO executions of any kind. `COUNT(*)` is 0 and
    // `MAX(started_at)` is NULL — the shape that used to fail the decode.
    let (count, last_failure) = repo
        .count_recent_auth_failures(wf, 7)
        .await
        .expect("an empty window is an answer, not an error");

    assert_eq!(count, 0, "no matching executions means zero failures");
    assert_eq!(
        last_failure, None,
        "MAX over an empty set has no meaningful zero — it must stay absent \
         rather than be COALESCEd into a fabricated timestamp"
    );
}

#[tokio::test]
async fn auth_failure_count_for_an_unknown_workflow_still_returns_a_row() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = talos_analytics_repository::AnalyticsRepository::new(pool.clone());

    // Pins the structural fact that retired the `fetch_optional` here: an
    // ungrouped aggregate returns EXACTLY ONE ROW even when nothing matches
    // and the workflow does not exist at all. Any caller branching on a
    // "no row" case was reading dead code; `count == 0` is the real signal.
    let (count, last_failure) = repo
        .count_recent_auth_failures(Uuid::new_v4(), 7)
        .await
        .expect("ungrouped aggregate always produces a row");

    assert_eq!(count, 0);
    assert_eq!(last_failure, None);
}

#[tokio::test]
async fn auth_failure_count_reports_the_most_recent_failure_when_there_are_some() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = talos_analytics_repository::AnalyticsRepository::new(pool.clone());

    let user = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let actor = Uuid::new_v4();
    seed_user(&pool, user, "authfail-some@quality.test").await;
    seed_workflow(&pool, wf, user, "pa-blocked-vault-path").await;
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'authfail-actor')")
        .bind(actor)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed actor");

    // Two in-window auth failures, one in-window failure with an unrelated
    // error, and one auth failure OUTSIDE the 7-day window. Only the first
    // two may count, and `last_failure` must be the newer of them.
    let rows = [
        ("failed", Some("HTTP 401 unauthorized"), 1_i64),
        ("failed", Some("access denied for vault path"), 3),
        ("failed", Some("connection reset by peer"), 2),
        ("failed", Some("unauthorized"), 30),
    ];
    for (status, err, days_ago) in rows {
        sqlx::query(
            "INSERT INTO workflow_executions \
                 (id, workflow_id, user_id, status, actor_id, error_message, started_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW() - make_interval(days => $7::int))",
        )
        .bind(Uuid::new_v4())
        .bind(wf)
        .bind(user)
        .bind(status)
        .bind(actor)
        .bind(err)
        .bind(days_ago as i32)
        .execute(&pool)
        .await
        .expect("seed execution");
    }

    let (count, last_failure) = repo
        .count_recent_auth_failures(wf, 7)
        .await
        .expect("populated window");

    assert_eq!(
        count, 2,
        "only in-window executions whose error matches the auth patterns count"
    );
    let last = last_failure.expect("count > 0 implies a MAX over a NOT NULL column");
    // The newest matching failure is the 1-day-old one, so the reported
    // timestamp must be newer than 2 days ago.
    let parsed = chrono::DateTime::parse_from_str(&last, "%Y-%m-%d %H:%M:%S%.f%#z")
        .map(|d| d.with_timezone(&chrono::Utc))
        .expect("MAX(started_at)::text parses as a timestamp");
    assert!(
        parsed > chrono::Utc::now() - chrono::Duration::days(2),
        "last_failure must be the MOST RECENT matching failure, got {last}"
    );
}
