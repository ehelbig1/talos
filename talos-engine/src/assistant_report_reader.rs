//! Postgres impl of [`talos_workflow_engine_core::AssistantReportReader`]
//! — the read port behind the `assistant_report` system node.
//!
//! Composes the DOMAIN crates rather than owning SQL: executions +
//! fuel from `talos_execution_repository`, ops-alerts week stats +
//! correction candidates from `talos_ops_alerts_repository`, and ML
//! loop health from `talos_ml::loop_health`. Tenancy: every query is
//! scoped by the `user_id` the engine passes in (the execution's
//! resolved identity — node config carries no identity).

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;
use talos_execution_repository::ExecutionRepository;
use talos_ops_alerts_repository::OpsAlertRepository;
use uuid::Uuid;

pub struct PostgresAssistantReportReader {
    pool: PgPool,
    executions: ExecutionRepository,
    ops_alerts: OpsAlertRepository,
}

impl PostgresAssistantReportReader {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            executions: ExecutionRepository::new(pool.clone()),
            ops_alerts: OpsAlertRepository::new(pool.clone()),
            pool,
        }
    }
}

#[async_trait]
impl talos_workflow_engine_core::AssistantReportReader for PostgresAssistantReportReader {
    async fn snapshot(
        &self,
        user_id: Uuid,
        days: u32,
    ) -> Result<JsonValue, talos_workflow_engine_core::BoxError> {
        let days = days.clamp(1, 31) as i32;

        let workflows = self.executions.weekly_workflow_stats(user_id, days).await?;
        let (fuel_total, wall_ms_total) = self.executions.weekly_fuel_totals(user_id, days).await?;
        let (opened, auto_resolved, operator_resolved, corrected, reopened) =
            self.ops_alerts.week_stats(user_id, days).await?;
        let candidates = self.ops_alerts.correction_candidates(user_id, 5).await?;

        // One-click correction links for the candidates — shared
        // batched/time-boxed/best-effort helper (see
        // correction_links.rs for the write-inside-read-port rationale).
        let base_url = talos_public_url::public_base_url_or(talos_config::get_base_url);
        let candidate_ids: Vec<Uuid> = candidates.iter().map(|a| a.id).collect();
        let candidate_urls = talos_ops_alerts_repository::correction_links::mint_correction_urls(
            &self.ops_alerts,
            user_id,
            &candidate_ids,
            &base_url,
        )
        .await;

        let ml = talos_ml::loop_health(&self.pool, user_id).await?;

        Ok(json!({
            "window_days": days,
            "workflows": workflows.iter().map(|(name, total, completed, failed)| json!({
                "name": name,
                "runs": total,
                "completed": completed,
                "failed": failed,
            })).collect::<Vec<_>>(),
            "cost": {
                "fuel_total": fuel_total,
                "wall_time_ms_total": wall_ms_total,
            },
            "ops_alerts": {
                "opened": opened,
                "auto_resolved": auto_resolved,
                "operator_resolved": operator_resolved,
                "corrected": corrected,
                "reopened": reopened,
                "correction_candidates": candidates.iter().zip(candidate_urls.iter())
                    .map(|(a, url)| json!({
                        "id": a.id,
                        "correction_url": url,
                        "title": a.title,
                        "severity": a.severity,
                        "source": a.source,
                        "occurrence_count": a.occurrence_count,
                    })).collect::<Vec<_>>(),
            },
            "ml": ml,
        }))
    }
}
