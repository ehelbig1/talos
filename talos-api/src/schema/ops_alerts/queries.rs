//! Ops-alerts GraphQL queries — the triage list + digest rollup.

use async_graphql::{Context, Object, Result, SimpleObject};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::super::{require_scope, SafeErrorExtensions};
use talos_ops_alerts_repository::{
    OpsAlertDigest as RepoDigest, OpsAlertFilter, OpsAlertRepository, OpsAlertRow,
};

/// One normalized operational alert as surfaced to the triage UI. Field set
/// mirrors [`OpsAlertRow`]; `severity` is the effective label (a human
/// correction overrides the classifier), `correctedSeverity` is set only when
/// a human corrected it (the distillation gold signal).
#[derive(SimpleObject, Clone)]
pub struct OpsAlert {
    pub id: Uuid,
    pub source: String,
    pub external_id: Option<String>,
    pub dedup_key: String,
    pub title: String,
    pub resource: Option<String>,
    pub severity: String,
    pub severity_raw: Option<String>,
    /// `heuristic` | `classifier` | `correction`, when triaged.
    pub triage_source: Option<String>,
    pub triage_confidence: Option<f32>,
    pub corrected_severity: Option<String>,
    /// `new` | `acked` | `resolved`.
    pub status: String,
    pub occurrence_count: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Set when the alert re-fired AFTER being resolved (regression).
    pub reopened_at: Option<DateTime<Utc>>,
    /// `operator` | `signal`, when resolved.
    pub resolved_source: Option<String>,
}

impl From<OpsAlertRow> for OpsAlert {
    fn from(r: OpsAlertRow) -> Self {
        Self {
            id: r.id,
            source: r.source,
            external_id: r.external_id,
            dedup_key: r.dedup_key,
            title: r.title,
            resource: r.resource,
            severity: r.severity,
            severity_raw: r.severity_raw,
            triage_source: r.triage_source,
            triage_confidence: r.triage_confidence,
            corrected_severity: r.corrected_severity,
            status: r.status,
            occurrence_count: r.occurrence_count,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            reopened_at: r.reopened_at,
            resolved_source: r.resolved_source,
        }
    }
}

/// `(severity, count)` over the active set.
#[derive(SimpleObject, Clone)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

/// `(source, count)` over the active set.
#[derive(SimpleObject, Clone)]
pub struct SourceCount {
    pub source: String,
    pub count: i64,
}

/// Digest rollup over the active (non-resolved) alert set.
#[derive(SimpleObject, Clone)]
pub struct OpsAlertsDigest {
    pub active_by_severity: Vec<SeverityCount>,
    pub active_by_source: Vec<SourceCount>,
    pub new_last_24h: i64,
    pub reopened_active: i64,
}

impl From<RepoDigest> for OpsAlertsDigest {
    fn from(d: RepoDigest) -> Self {
        Self {
            active_by_severity: d
                .active_by_severity
                .into_iter()
                .map(|(severity, count)| SeverityCount { severity, count })
                .collect(),
            active_by_source: d
                .active_by_source
                .into_iter()
                .map(|(source, count)| SourceCount { source, count })
                .collect(),
            new_last_24h: d.new_last_24h,
            reopened_active: d.reopened_active,
        }
    }
}

#[derive(Default)]
pub struct OpsAlertsQueries;

#[Object]
impl OpsAlertsQueries {
    /// The caller's alerts, owner-scoped, newest activity first. With no
    /// explicit `status` the triage default excludes resolved rows; an
    /// explicit `status` filter overrides that.
    async fn ops_alerts(
        &self,
        ctx: &Context<'_>,
        status: Option<String>,
        severity: Option<String>,
        source: Option<String>,
        limit: Option<i32>,
    ) -> Result<Vec<OpsAlert>> {
        // Scope gate (lint check 22 — sibling mutations exist). Session
        // callers pass any scope; API keys need WorkflowsRead.
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        let filter = OpsAlertFilter {
            // Triage default: hide resolved unless an explicit status is set.
            exclude_resolved: status.is_none(),
            status,
            severity,
            source,
            since: None,
            limit: limit.map(i64::from),
        };
        let rows = OpsAlertRepository::new(db_pool.clone())
            .list(user_id, filter)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ops_alerts", error = %e, "ops_alerts query failed");
                async_graphql::Error::new("Could not load alerts").extend_safe()
            })?;
        Ok(rows.into_iter().map(OpsAlert::from).collect())
    }

    /// Digest rollup over the caller's active alert set.
    async fn ops_alerts_digest(&self, ctx: &Context<'_>) -> Result<OpsAlertsDigest> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        let digest = OpsAlertRepository::new(db_pool.clone())
            .digest(user_id)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ops_alerts", error = %e, "ops_alerts_digest query failed");
                async_graphql::Error::new("Could not load alert digest").extend_safe()
            })?;
        Ok(digest.into())
    }
}

/// Session user_id from the auth context — never a query argument.
pub(super) fn session_user(ctx: &Context<'_>) -> Result<Uuid> {
    ctx.data_opt::<Uuid>()
        .copied()
        .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())
}
