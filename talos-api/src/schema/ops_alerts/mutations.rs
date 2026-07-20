//! Ops-alerts GraphQL mutations — the operator triage actions
//! (correct severity / ack / resolve). Each returns whether a row actually
//! transitioned (the guarded-transition contract from the repository).

use async_graphql::{Context, Object, Result};
use uuid::Uuid;

use super::super::{require_2fa, require_scope, SafeErrorExtensions};
use talos_ops_alerts_repository::{OpsAlertRepository, ASSIGNABLE_SEVERITIES};

/// Static, caller-safe rejection for an out-of-range severity argument.
/// Kept in sync with [`ASSIGNABLE_SEVERITIES`] by a unit test — surfaced to
/// the client so the triage UI can render a precise inline error (no internal
/// detail; it lists only the fixed vocabulary).
const INVALID_SEVERITY_MSG: &str =
    "invalid severity — expected one of critical, high, medium, low, info, noise";

#[derive(Default)]
pub struct OpsAlertsMutations;

#[Object]
impl OpsAlertsMutations {
    /// Record a HUMAN severity correction — the distillation gold signal.
    /// Overwrites any classifier label and marks the row corrected. Returns
    /// true when a row transitioned (false = not found / not owned). The
    /// severity is validated against the assignable vocabulary in the resolver
    /// so the caller gets a specific, static message before any DB round-trip.
    async fn correct_ops_alert_severity(
        &self,
        ctx: &Context<'_>,
        alert_id: Uuid,
        severity: String,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = super::queries::session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        if !ASSIGNABLE_SEVERITIES.contains(&severity.trim()) {
            return Err(async_graphql::Error::new(INVALID_SEVERITY_MSG).extend_safe());
        }
        OpsAlertRepository::new(db_pool.clone())
            .correct_severity(user_id, alert_id, severity.trim())
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ops_alerts", error = %e, "correct_ops_alert_severity failed");
                async_graphql::Error::new("Could not correct alert severity").extend_safe()
            })
    }

    /// Acknowledge a `new` alert. Returns false when the row doesn't exist,
    /// isn't owned, or isn't `new` (guarded transition).
    async fn ack_ops_alert(&self, ctx: &Context<'_>, alert_id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = super::queries::session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        OpsAlertRepository::new(db_pool.clone())
            .ack(user_id, alert_id)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ops_alerts", error = %e, "ack_ops_alert failed");
                async_graphql::Error::new("Could not acknowledge alert").extend_safe()
            })
    }

    /// Resolve a `new`/`acked` alert (operator-sourced). Returns false when
    /// nothing matched. A later re-fire still reopens the row via ingest.
    async fn resolve_ops_alert(&self, ctx: &Context<'_>, alert_id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = super::queries::session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        OpsAlertRepository::new(db_pool.clone())
            .resolve(user_id, alert_id)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ops_alerts", error = %e, "resolve_ops_alert failed");
                async_graphql::Error::new("Could not resolve alert").extend_safe()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_ops_alerts_repository::{OpsAlertRow, ASSIGNABLE_SEVERITIES};

    /// Message-stability: the static invalid-severity string must name every
    /// assignable severity in order. If the vocabulary changes, this fails so
    /// the operator-facing message is updated deliberately.
    #[test]
    fn invalid_severity_message_is_the_exact_static_string() {
        assert_eq!(
            INVALID_SEVERITY_MSG,
            "invalid severity — expected one of critical, high, medium, low, info, noise"
        );
        // Every assignable label appears in the message (drift guard).
        for sev in ASSIGNABLE_SEVERITIES {
            assert!(
                INVALID_SEVERITY_MSG.contains(sev),
                "message must list assignable severity '{sev}'"
            );
        }
    }

    /// Pure mapping test for `From<OpsAlertRow> for OpsAlert` — every field is
    /// carried straight through (no lossy narrowing on the wire).
    #[test]
    fn ops_alert_from_row_carries_all_fields() {
        use chrono::Utc;
        let now = Utc::now();
        let id = uuid::Uuid::new_v4();
        let row = OpsAlertRow {
            id,
            source: "snyk-email".into(),
            external_id: Some("ext-1".into()),
            dedup_key: "snyk|ai-platform|FOO".into(),
            title: "Prototype pollution".into(),
            resource: Some("ai-platform".into()),
            severity_raw: Some("high".into()),
            severity: "critical".into(),
            triage_source: Some("correction".into()),
            triage_confidence: Some(0.5),
            corrected_severity: Some("critical".into()),
            status: "acked".into(),
            occurrence_count: 3,
            first_seen: now,
            last_seen: now,
            reopened_at: Some(now),
            resolved_source: None,
        };
        let a = super::super::queries::OpsAlert::from(row);
        assert_eq!(a.id, id);
        assert_eq!(a.source, "snyk-email");
        assert_eq!(a.external_id.as_deref(), Some("ext-1"));
        assert_eq!(a.severity, "critical");
        assert_eq!(a.corrected_severity.as_deref(), Some("critical"));
        assert_eq!(a.triage_confidence, Some(0.5));
        assert_eq!(a.occurrence_count, 3);
        assert_eq!(a.status, "acked");
        assert!(a.reopened_at.is_some());
        assert!(a.resolved_source.is_none());
    }
}
