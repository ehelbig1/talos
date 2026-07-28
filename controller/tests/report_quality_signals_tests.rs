//! Weekly self-report quality signals — teacher-audit ceilings +
//! observe-only judge scores.
//!
//! Covers the two new repository queries added for the `assistant_report`
//! node: `ExecutionRepository::{record_judge_score, weekly_judge_scores}`
//! (the judge-score insert + per-workflow aggregate) and
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

    for _ in 0..4 {
        let mut conn = pool.acquire().await.expect("acquire");
        ExecutionRepository::record_judge_score(
            &mut conn,
            wf,
            Uuid::new_v4(),
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
