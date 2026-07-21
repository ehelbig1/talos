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
        ExecutionRepository::record_judge_score(&mut conn, wf, node, exec, score, passed)
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
