//! `ops_alerts` repository — the durable store behind the alert-triage
//! pipeline (see `migrations/20260717170000_ops_alerts.sql` for the schema
//! and tenancy-posture rationale).
//!
//! Ownership: ALL SQL against `ops_alerts` lives here (repository-per-domain
//! mandate), and so does the `__ops_alert__` envelope protocol itself
//! ([`envelope`]). Writers: the engine's `__ops_alert__` node hook and the
//! module-result completion chokepoint (both delegating to
//! [`envelope::spawn_ingest_from_output`]) plus the MCP triage surface
//! (ack/resolve/correct). Readers: MCP list/digest tools.
//!
//! Invariants this crate enforces (not the callers):
//! * **Dedup bump never clobbers triage.** `ingest` upserts on
//!   `(user_id, dedup_key)`; on conflict it bumps `occurrence_count` /
//!   `last_seen` and refreshes descriptive fields, but `severity`,
//!   `triage_*`, and `corrected_*` are untouched — human corrections are the
//!   future distillation gold set and must survive re-ingestion.
//! * **Re-fired resolved alerts reopen.** A conflict against a `resolved`
//!   row flips it back to `new` (regression signal) and clears
//!   `resolved_at`; `acked` stays `acked` (the operator has seen it).
//! * **Classifier writes never overwrite corrections.** `record_triage`
//!   is a no-op on rows where `corrected_severity IS NOT NULL`.
//! * **Bounded inputs.** Text fields are char-truncated (never byte-sliced —
//!   the `&str[..N]` mid-codepoint panic class, MCP-477..479) and oversized
//!   `raw` payloads are dropped (alert kept) rather than rejected.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub mod envelope;

/// Severity labels a triage path may assign. `unclassified` is the ingest
/// default and deliberately NOT assignable by [`OpsAlertRepository::correct_severity`] /
/// [`OpsAlertRepository::record_triage`] — triage always moves an alert OUT of
/// `unclassified`, never back in.
pub const ASSIGNABLE_SEVERITIES: [&str; 6] = ["critical", "high", "medium", "low", "info", "noise"];

/// Char-based caps for ingested text fields (see module docs; chars, not
/// bytes, so truncation can't panic mid-codepoint).
const MAX_TITLE_CHARS: usize = 500;
const MAX_KEY_CHARS: usize = 500;
const MAX_SOURCE_CHARS: usize = 100;
const MAX_RESOURCE_CHARS: usize = 300;
/// Serialized cap for the DLP-redacted `raw` payload. Oversized payloads are
/// dropped (alert survives without `raw`) — an alert store must never refuse
/// an alert because its body was noisy.
const MAX_RAW_BYTES: usize = 64 * 1024;

/// Typed ingest error, mirroring `talos_memory::MemoryWriteError` (finding
/// N-5): classify at the source so the hook can emit a stable metric label
/// without substring-matching wrapped error strings.
#[derive(thiserror::Error, Debug)]
pub enum OpsAlertIngestError {
    #[error("ops-alert validation failed: {0}")]
    Validation(String),
    #[error("ops-alert db write failed")]
    Db(#[source] sqlx::Error),
}

impl OpsAlertIngestError {
    #[must_use]
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation",
            Self::Db(_) => "db",
        }
    }
}

/// A normalized alert ready for ingest — the shape parser modules emit under
/// the `__ops_alert__` node-output key.
#[derive(Debug, Clone)]
pub struct NewOpsAlert {
    pub source: String,
    pub external_id: Option<String>,
    pub dedup_key: String,
    pub title: String,
    pub resource: Option<String>,
    pub severity_raw: Option<String>,
    /// Initial severity for a NEWLY created row only (parser heuristic or
    /// classifier output). Ignored on dedup-bump. Must be an
    /// [`ASSIGNABLE_SEVERITIES`] value; anything else lands `unclassified`.
    pub severity_hint: Option<String>,
    /// DLP-REDACTED source payload. Callers redact BEFORE constructing this
    /// (the hook does); this crate only bounds its size.
    pub raw: Option<serde_json::Value>,
}

/// Outcome of an [`OpsAlertRepository::ingest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    Created {
        id: Uuid,
    },
    /// The fingerprint already existed: occurrence bumped. `reopened` is true
    /// when the prior row was `resolved` (regression signal).
    Bumped {
        id: Uuid,
        occurrence_count: i32,
        reopened: bool,
    },
}

/// One `ops_alerts` row as surfaced to the triage tools.
#[derive(Debug, Clone)]
pub struct OpsAlertRow {
    pub id: Uuid,
    pub source: String,
    pub external_id: Option<String>,
    pub dedup_key: String,
    pub title: String,
    pub resource: Option<String>,
    pub severity_raw: Option<String>,
    pub severity: String,
    pub triage_source: Option<String>,
    pub triage_confidence: Option<f32>,
    pub corrected_severity: Option<String>,
    pub status: String,
    pub occurrence_count: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Set when the alert re-fired AFTER being resolved (regression); the
    /// most recent such moment. NULL = never reopened.
    pub reopened_at: Option<DateTime<Utc>>,
}

/// Filters for [`OpsAlertRepository::list`]. All optional; `limit` is clamped
/// server-side (caller-supplied-limit class, lint 12).
#[derive(Debug, Clone, Default)]
pub struct OpsAlertFilter {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
}

/// Digest counts over the active (non-resolved) set.
#[derive(Debug, Clone, Default)]
pub struct OpsAlertDigest {
    /// `(severity, count)` over active alerts, descending count.
    pub active_by_severity: Vec<(String, i64)>,
    /// `(source, count)` over active alerts, descending count.
    pub active_by_source: Vec<(String, i64)>,
    pub new_last_24h: i64,
    pub reopened_active: i64,
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.trim().chars().take(max).collect()
}

/// Validate a severity label against [`ASSIGNABLE_SEVERITIES`].
pub fn validate_severity(s: &str) -> Result<&str, String> {
    let t = s.trim();
    if ASSIGNABLE_SEVERITIES.contains(&t) {
        Ok(t)
    } else {
        Err(format!(
            "invalid severity '{t}' (expected one of {ASSIGNABLE_SEVERITIES:?})"
        ))
    }
}

pub struct OpsAlertRepository {
    db_pool: PgPool,
}

impl OpsAlertRepository {
    #[must_use]
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    /// Normalize + bound a [`NewOpsAlert`] for insertion. Pure — split out so
    /// the bounding rules are unit-testable without Postgres (house testing
    /// convention: tests exercise real production code).
    pub(crate) fn sanitize(a: NewOpsAlert) -> Result<NewOpsAlert, OpsAlertIngestError> {
        let source = truncate_chars(&a.source, MAX_SOURCE_CHARS);
        let dedup_key = truncate_chars(&a.dedup_key, MAX_KEY_CHARS);
        let title = truncate_chars(&a.title, MAX_TITLE_CHARS);
        if source.is_empty() {
            return Err(OpsAlertIngestError::Validation("empty source".into()));
        }
        if dedup_key.is_empty() {
            return Err(OpsAlertIngestError::Validation("empty dedup_key".into()));
        }
        if title.is_empty() {
            return Err(OpsAlertIngestError::Validation("empty title".into()));
        }
        // Oversized raw is DROPPED, not rejected: the alert itself must land.
        let raw = a.raw.filter(|v| {
            serde_json::to_vec(v)
                .map(|b| b.len() <= MAX_RAW_BYTES)
                .unwrap_or(false)
        });
        // Invalid hints degrade to None (→ 'unclassified'), they don't block.
        let severity_hint = a
            .severity_hint
            .as_deref()
            .and_then(|s| validate_severity(s).ok())
            .map(str::to_string);
        Ok(NewOpsAlert {
            source,
            external_id: a.external_id.map(|s| truncate_chars(&s, MAX_KEY_CHARS)),
            dedup_key,
            title,
            resource: a.resource.map(|s| truncate_chars(&s, MAX_RESOURCE_CHARS)),
            severity_raw: a.severity_raw.map(|s| truncate_chars(&s, MAX_SOURCE_CHARS)),
            severity_hint,
            raw,
        })
    }

    /// Upsert an alert for `user_id` (see module docs for the bump/reopen/
    /// never-clobber-triage invariants). `org_id` is stamped on CREATE only.
    pub async fn ingest(
        &self,
        user_id: Uuid,
        org_id: Option<Uuid>,
        alert: NewOpsAlert,
    ) -> Result<IngestOutcome, OpsAlertIngestError> {
        let a = Self::sanitize(alert)?;
        // `prev` captures the pre-upsert status so the outcome can report
        // created-vs-bumped-vs-reopened without a second round-trip.
        let row = sqlx::query(
            r#"
            WITH prev AS (
                SELECT status FROM ops_alerts WHERE user_id = $1 AND dedup_key = $4
            )
            INSERT INTO ops_alerts
                (user_id, org_id, source, dedup_key, external_id, title, resource,
                 severity_raw, severity, triage_source, raw)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8,
                 COALESCE($9, 'unclassified'),
                 CASE WHEN $9 IS NULL THEN NULL ELSE 'heuristic' END,
                 $10)
            ON CONFLICT (user_id, dedup_key) DO UPDATE SET
                occurrence_count = ops_alerts.occurrence_count + 1,
                last_seen  = NOW(),
                title      = EXCLUDED.title,
                external_id = COALESCE(EXCLUDED.external_id, ops_alerts.external_id),
                resource   = COALESCE(EXCLUDED.resource, ops_alerts.resource),
                severity_raw = COALESCE(EXCLUDED.severity_raw, ops_alerts.severity_raw),
                raw        = COALESCE(EXCLUDED.raw, ops_alerts.raw),
                status     = CASE WHEN ops_alerts.status = 'resolved'
                                  THEN 'new' ELSE ops_alerts.status END,
                resolved_at = CASE WHEN ops_alerts.status = 'resolved'
                                   THEN NULL ELSE ops_alerts.resolved_at END,
                -- Stamp the reopen moment; resolved_at is cleared above so
                -- this column is the only durable evidence of a regression.
                reopened_at = CASE WHEN ops_alerts.status = 'resolved'
                                   THEN NOW() ELSE ops_alerts.reopened_at END
            RETURNING id, occurrence_count, (SELECT status FROM prev) AS prev_status
            "#,
        )
        .bind(user_id)
        .bind(org_id)
        .bind(&a.source)
        .bind(&a.dedup_key)
        .bind(&a.external_id)
        .bind(&a.title)
        .bind(&a.resource)
        .bind(&a.severity_raw)
        .bind(&a.severity_hint)
        .bind(&a.raw)
        .fetch_one(&self.db_pool)
        .await
        .map_err(OpsAlertIngestError::Db)?;

        let id: Uuid = row.try_get("id").map_err(OpsAlertIngestError::Db)?;
        let occurrence_count: i32 = row
            .try_get("occurrence_count")
            .map_err(OpsAlertIngestError::Db)?;
        let prev_status: Option<String> = row
            .try_get::<Option<String>, _>("prev_status")
            .map_err(OpsAlertIngestError::Db)?;
        Ok(match prev_status {
            None => IngestOutcome::Created { id },
            Some(prev) => IngestOutcome::Bumped {
                id,
                occurrence_count,
                reopened: prev == "resolved",
            },
        })
    }

    /// List alerts for `user_id`, newest activity first. `limit` clamps to
    /// [1, 200] (default 50).
    pub async fn list(&self, user_id: Uuid, filter: OpsAlertFilter) -> Result<Vec<OpsAlertRow>> {
        let limit = filter.limit.unwrap_or(50).clamp(1, 200);
        let rows = sqlx::query(
            r#"
            SELECT id, source, external_id, dedup_key, title, resource,
                   severity_raw, severity, triage_source, triage_confidence,
                   corrected_severity, status, occurrence_count,
                   first_seen, last_seen, reopened_at
            FROM ops_alerts
            WHERE user_id = $1
              AND ($2::text IS NULL OR status = $2)
              AND ($3::text IS NULL OR severity = $3)
              AND ($4::text IS NULL OR source = $4)
              AND ($5::timestamptz IS NULL OR last_seen >= $5)
            ORDER BY last_seen DESC, id DESC
            LIMIT $6
            "#,
        )
        .bind(user_id)
        .bind(&filter.status)
        .bind(&filter.severity)
        .bind(&filter.source)
        .bind(filter.since)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter().map(Self::row_to_alert).collect()
    }

    /// Map a full-projection `ops_alerts` row (the SELECT list shared by
    /// [`Self::list`] and [`Self::list_active_ranked`]) into
    /// [`OpsAlertRow`]. Fail-loud `try_get` per checks 52/55.
    fn row_to_alert(r: sqlx::postgres::PgRow) -> Result<OpsAlertRow> {
        Ok(OpsAlertRow {
            id: r.try_get("id")?,
            source: r.try_get("source")?,
            external_id: r.try_get::<Option<_>, _>("external_id")?,
            dedup_key: r.try_get("dedup_key")?,
            title: r.try_get("title")?,
            resource: r.try_get::<Option<_>, _>("resource")?,
            severity_raw: r.try_get::<Option<_>, _>("severity_raw")?,
            severity: r.try_get("severity")?,
            triage_source: r.try_get::<Option<_>, _>("triage_source")?,
            triage_confidence: r.try_get::<Option<_>, _>("triage_confidence")?,
            corrected_severity: r.try_get::<Option<_>, _>("corrected_severity")?,
            status: r.try_get("status")?,
            occurrence_count: r.try_get("occurrence_count")?,
            first_seen: r.try_get("first_seen")?,
            last_seen: r.try_get("last_seen")?,
            reopened_at: r.try_get::<Option<_>, _>("reopened_at")?,
        })
    }

    /// Acknowledge a `new` alert. Returns false when the row doesn't exist,
    /// isn't owned, or isn't `new` (guarded transition — no clobbering a
    /// concurrent resolve; the status-guard write class, lint 39 spirit).
    pub async fn ack(&self, user_id: Uuid, alert_id: Uuid) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE ops_alerts SET status = 'acked', acked_at = NOW() \
             WHERE id = $1 AND user_id = $2 AND status = 'new'",
        )
        .bind(alert_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Resolve a `new`/`acked` alert. Returns false when nothing matched.
    pub async fn resolve(&self, user_id: Uuid, alert_id: Uuid) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE ops_alerts SET status = 'resolved', resolved_at = NOW() \
             WHERE id = $1 AND user_id = $2 AND status IN ('new','acked')",
        )
        .bind(alert_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Record a HUMAN severity correction — the distillation gold signal.
    /// Overwrites any classifier label and marks the row corrected.
    pub async fn correct_severity(
        &self,
        user_id: Uuid,
        alert_id: Uuid,
        severity: &str,
    ) -> Result<bool> {
        let sev = validate_severity(severity).map_err(anyhow::Error::msg)?;
        let res = sqlx::query(
            "UPDATE ops_alerts SET severity = $3, corrected_severity = $3, \
                 corrected_at = NOW(), triage_source = 'correction' \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(alert_id)
        .bind(user_id)
        .bind(sev)
        .execute(&self.db_pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Record a CLASSIFIER triage label. Never overwrites a human correction
    /// (`corrected_severity IS NULL` guard) — corrections outrank models.
    pub async fn record_triage(
        &self,
        user_id: Uuid,
        alert_id: Uuid,
        severity: &str,
        triage_source: &str,
        confidence: Option<f32>,
    ) -> Result<bool> {
        let sev = validate_severity(severity).map_err(anyhow::Error::msg)?;
        let res = sqlx::query(
            "UPDATE ops_alerts SET severity = $3, triage_source = $4, triage_confidence = $5 \
             WHERE id = $1 AND user_id = $2 AND corrected_severity IS NULL",
        )
        .bind(alert_id)
        .bind(user_id)
        .bind(sev)
        .bind(truncate_chars(triage_source, MAX_SOURCE_CHARS))
        .bind(confidence)
        .execute(&self.db_pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Digest counts over the user's alerts (see [`OpsAlertDigest`]).
    /// List ACTIVE (non-resolved) alerts ranked by triage priority:
    /// severity first (critical > high > medium > unclassified > low >
    /// info > noise — unclassified sits mid-rank because a human hasn't
    /// looked yet), then most-recent activity. Powers the
    /// `ops_alerts_digest` system node's `top_active` section; `limit`
    /// clamps to [1, 25] (a briefing slice, not a pagination surface —
    /// use [`Self::list`] for the full triage view).
    pub async fn list_active_ranked(&self, user_id: Uuid, limit: i64) -> Result<Vec<OpsAlertRow>> {
        let limit = limit.clamp(1, 25);
        let rows = sqlx::query(
            r#"
            SELECT id, source, external_id, dedup_key, title, resource,
                   severity_raw, severity, triage_source, triage_confidence,
                   corrected_severity, status, occurrence_count,
                   first_seen, last_seen, reopened_at
            FROM ops_alerts
            WHERE user_id = $1 AND status <> 'resolved'
            ORDER BY CASE severity
                       WHEN 'critical' THEN 0
                       WHEN 'high' THEN 1
                       WHEN 'medium' THEN 2
                       WHEN 'unclassified' THEN 3
                       WHEN 'low' THEN 4
                       WHEN 'info' THEN 5
                       ELSE 6
                     END,
                     last_seen DESC, id DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter().map(Self::row_to_alert).collect()
    }

    pub async fn digest(&self, user_id: Uuid) -> Result<OpsAlertDigest> {
        let sev_rows = sqlx::query(
            "SELECT severity, COUNT(*) AS n FROM ops_alerts \
             WHERE user_id = $1 AND status <> 'resolved' \
             GROUP BY severity ORDER BY n DESC, severity",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        let src_rows = sqlx::query(
            "SELECT source, COUNT(*) AS n FROM ops_alerts \
             WHERE user_id = $1 AND status <> 'resolved' \
             GROUP BY source ORDER BY n DESC, source",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        let scalars = sqlx::query(
            // `reopened_at IS NOT NULL` is the precise regression signal
            // (stamped by the ingest upsert the moment a resolved row
            // reopens). The first-cut heuristic (`occurrence_count > 1 AND
            // …`) counted bumped-while-new rows as "reopened" — observed
            // live 2026-07-17 reporting 4 reopens on never-resolved alerts.
            "SELECT \
               COUNT(*) FILTER (WHERE status = 'new' \
                                AND first_seen >= NOW() - INTERVAL '24 hours') AS new_24h, \
               COUNT(*) FILTER (WHERE status <> 'resolved' \
                                AND reopened_at IS NOT NULL) AS reopened \
             FROM ops_alerts WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;

        let mut digest = OpsAlertDigest {
            new_last_24h: scalars.try_get("new_24h")?,
            reopened_active: scalars.try_get("reopened")?,
            ..Default::default()
        };
        for r in sev_rows {
            digest
                .active_by_severity
                .push((r.try_get("severity")?, r.try_get("n")?));
        }
        for r in src_rows {
            digest
                .active_by_source
                .push((r.try_get("source")?, r.try_get("n")?));
        }
        Ok(digest)
    }

    /// Retention: delete `resolved` alerts older than `days` (rejects
    /// non-positive values — the negative-interval full-purge footgun class,
    /// MCP-997).
    pub async fn delete_resolved_older_than(&self, user_id: Uuid, days: i32) -> Result<u64> {
        if days <= 0 {
            anyhow::bail!("retention days must be positive (got {days})");
        }
        let res = sqlx::query(
            "DELETE FROM ops_alerts \
             WHERE user_id = $1 AND status = 'resolved' \
               AND resolved_at < NOW() - make_interval(days => $2::int)",
        )
        .bind(user_id)
        .bind(days)
        .execute(&self.db_pool)
        .await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_alert() -> NewOpsAlert {
        NewOpsAlert {
            source: "snyk-email".into(),
            external_id: None,
            dedup_key: "snyk|ai-platform|SNYK-JS-FOO-123".into(),
            title: "Prototype pollution in foo".into(),
            resource: Some("ai-platform".into()),
            severity_raw: Some("high".into()),
            severity_hint: Some("high".into()),
            raw: Some(serde_json::json!({"ok": true})),
        }
    }

    #[test]
    fn sanitize_rejects_empty_identity_fields() {
        for field in ["source", "dedup_key", "title"] {
            let mut a = base_alert();
            match field {
                "source" => a.source = "   ".into(),
                "dedup_key" => a.dedup_key = String::new(),
                _ => a.title = "\t".into(),
            }
            let err = OpsAlertRepository::sanitize(a).unwrap_err();
            assert_eq!(err.metric_label(), "validation", "field: {field}");
        }
    }

    #[test]
    fn sanitize_truncates_by_chars_not_bytes() {
        // Multi-byte codepoints at the boundary must not panic (the
        // byte-slice UTF-8 panic class, MCP-477..479) and must count CHARS.
        let mut a = base_alert();
        a.title = "é".repeat(600);
        let s = OpsAlertRepository::sanitize(a).unwrap();
        assert_eq!(s.title.chars().count(), 500);
    }

    #[test]
    fn sanitize_drops_oversized_raw_but_keeps_alert() {
        let mut a = base_alert();
        a.raw = Some(serde_json::json!({ "blob": "x".repeat(70 * 1024) }));
        let s = OpsAlertRepository::sanitize(a).unwrap();
        assert!(s.raw.is_none(), "oversized raw dropped");
        assert!(!s.title.is_empty(), "alert itself survives");
    }

    #[test]
    fn sanitize_degrades_invalid_severity_hint_to_none() {
        let mut a = base_alert();
        a.severity_hint = Some("catastrophic".into());
        let s = OpsAlertRepository::sanitize(a).unwrap();
        assert!(
            s.severity_hint.is_none(),
            "invalid hint → unclassified, not an error"
        );

        let mut b = base_alert();
        b.severity_hint = Some("  noise ".into());
        assert_eq!(
            OpsAlertRepository::sanitize(b)
                .unwrap()
                .severity_hint
                .as_deref(),
            Some("noise"),
            "valid hint trimmed + kept"
        );
    }

    #[test]
    fn validate_severity_rejects_unclassified_and_unknown() {
        // 'unclassified' is the ingest default, not an assignable label.
        assert!(validate_severity("unclassified").is_err());
        assert!(validate_severity("sev1").is_err());
        assert!(validate_severity("critical").is_ok());
    }
}
