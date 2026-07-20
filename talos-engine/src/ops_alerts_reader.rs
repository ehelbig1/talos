//! Postgres impl of [`talos_workflow_engine_core::OpsAlertsReader`] —
//! the read port behind the `ops_alerts_digest` system node.
//!
//! Thin adapter over [`talos_ops_alerts_repository::OpsAlertRepository`]
//! (all SQL stays in the domain crate). Tenancy: every query is scoped
//! by the `user_id` the engine passes in, which comes from the
//! execution's resolved identity — node config carries no identity.

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;
use talos_ops_alerts_repository::OpsAlertRepository;
use uuid::Uuid;

pub struct PostgresOpsAlertsReader {
    repo: OpsAlertRepository,
}

impl PostgresOpsAlertsReader {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: OpsAlertRepository::new(pool),
        }
    }
}

#[async_trait]
impl talos_workflow_engine_core::OpsAlertsReader for PostgresOpsAlertsReader {
    async fn snapshot(
        &self,
        user_id: Uuid,
        top_limit: u32,
    ) -> Result<JsonValue, talos_workflow_engine_core::BoxError> {
        let digest = self.repo.digest(user_id).await?;
        let top = self
            .repo
            .list_active_ranked(user_id, i64::from(top_limit))
            .await?;

        // One-click correction links: one capability token per listed
        // alert (batched mint), URL base from the public-URL resolver.
        // Best-effort — a minting failure degrades to a link-less
        // digest, never a failed one.
        let base_url = talos_public_url::public_base_url_or(talos_config::get_base_url);
        let alert_ids: Vec<Uuid> = top.iter().map(|a| a.id).collect();
        let correction_urls: Vec<Option<String>> = match self
            .repo
            .mint_correction_tokens(
                user_id,
                &alert_ids,
                talos_ops_alerts_repository::correction_links::DEFAULT_TOKEN_TTL_HOURS,
            )
            .await
        {
            Ok(tokens) => tokens
                .iter()
                .map(|t| {
                    Some(
                        talos_ops_alerts_repository::correction_links::correction_url(&base_url, t),
                    )
                })
                .collect(),
            Err(e) => {
                tracing::warn!(
                    target: "talos_corrections",
                    error = %e,
                    "correction-token mint failed — digest renders without links"
                );
                vec![None; top.len()]
            }
        };

        Ok(json!({
            "digest": {
                "active_by_severity": digest.active_by_severity.iter()
                    .map(|(s, n)| json!({"severity": s, "count": n}))
                    .collect::<Vec<_>>(),
                "active_by_source": digest.active_by_source.iter()
                    .map(|(s, n)| json!({"source": s, "count": n}))
                    .collect::<Vec<_>>(),
                "new_last_24h": digest.new_last_24h,
                "reopened_active": digest.reopened_active,
            },
            "top_active": top.iter().zip(correction_urls.iter()).map(|(a, url)| json!({
                "id": a.id,
                "correction_url": url,
                "title": a.title,
                "severity": a.severity,
                "source": a.source,
                "status": a.status,
                "resource": a.resource,
                "external_id": a.external_id,
                "occurrence_count": a.occurrence_count,
                "corrected": a.corrected_severity.is_some(),
                "reopened": a.reopened_at.is_some(),
                "first_seen": a.first_seen.to_rfc3339(),
                "last_seen": a.last_seen.to_rfc3339(),
            })).collect::<Vec<_>>(),
        }))
    }
}
