//! Postgres impl of [`talos_workflow_engine_core::JudgeScoreRecorder`] —
//! the write port behind observe-only judge verdicts.
//!
//! Thin, BEST-EFFORT adapter over
//! [`talos_execution_repository::ExecutionRepository::record_judge_score`]
//! (all SQL stays in the domain crate). A failed insert is logged and
//! dropped — it MUST NEVER fail the workflow (the engine also calls this
//! off the hot path via `tokio::spawn`). DLP: only the score + pass
//! boolean are persisted, never the judge reasoning/feedback text.

use async_trait::async_trait;
use sqlx::PgPool;
use talos_execution_repository::ExecutionRepository;
use uuid::Uuid;

pub struct PostgresJudgeScoreRecorder {
    pool: PgPool,
}

impl PostgresJudgeScoreRecorder {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl talos_workflow_engine_core::JudgeScoreRecorder for PostgresJudgeScoreRecorder {
    async fn record(
        &self,
        workflow_id: Uuid,
        node_id: Uuid,
        execution_id: Uuid,
        score: f64,
        passed: bool,
    ) {
        // Acquire a pooled connection and hand it to the conn-taking repo
        // method. Every failure path (acquire OR insert) is swallowed with
        // a warning — a judge-score record never blocks or fails the run.
        let mut conn = match self.pool.acquire().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    %execution_id, %node_id,
                    error = %e,
                    "judge-score record: failed to acquire DB connection; dropping"
                );
                return;
            }
        };
        if let Err(e) = ExecutionRepository::record_judge_score(
            &mut conn,
            workflow_id,
            node_id,
            execution_id,
            score,
            passed,
        )
        .await
        {
            tracing::warn!(
                %execution_id, %node_id,
                error = %e,
                "judge-score record: insert failed; dropping"
            );
        }
    }
}
