//! The one `ops_alerts` write (package CD, 2026-09-17).
//!
//! `talos-ops-alerts-repository` owns every other statement over `ops_alerts`
//! and re-exports what is here. The INSERT moved into this leaf because the
//! crates that DECIDE an actor-budget refusal (the actor and workflow
//! repositories) sit below that repository — it depends on
//! `talos-actor-repository` — and `on_budget_exceeded = 'alert'` raises an
//! alert from there. The dedup-bump / reopen / never-clobber-triage invariants
//! the upsert enforces are documented in that repository's crate docs.

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Severity labels a triage path may assign. `unclassified` is the ingest
/// default and deliberately NOT assignable by `correct_severity` /
/// `record_triage` — triage always moves an alert OUT of
/// `unclassified`, never back in.
pub const ASSIGNABLE_SEVERITIES: [&str; 6] = ["critical", "high", "medium", "low", "info", "noise"];

/// Char-based caps for ingested text fields (see module docs; chars, not
/// bytes, so truncation can't panic mid-codepoint).
pub const MAX_TITLE_CHARS: usize = 500;
pub const MAX_KEY_CHARS: usize = 500;
pub const MAX_SOURCE_CHARS: usize = 100;
pub const MAX_RESOURCE_CHARS: usize = 300;
/// Serialized cap for the DLP-redacted `raw` payload. Oversized payloads are
/// dropped (alert survives without `raw`) — an alert store must never refuse
/// an alert because its body was noisy.
pub const MAX_RAW_BYTES: usize = 64 * 1024;

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

/// Outcome of an [`ingest`].
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

pub fn truncate_chars(s: &str, max: usize) -> String {
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

/// Normalize + bound a [`NewOpsAlert`] for insertion. Pure — split out so
/// the bounding rules are unit-testable without Postgres (house testing
/// convention: tests exercise real production code).
pub fn sanitize(a: NewOpsAlert) -> Result<NewOpsAlert, OpsAlertIngestError> {
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
    pool: &PgPool,
    user_id: Uuid,
    org_id: Option<Uuid>,
    alert: NewOpsAlert,
) -> Result<IngestOutcome, OpsAlertIngestError> {
    let a = sanitize(alert)?;
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
    .fetch_one(pool)
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

/// The `(user_id, org_id)` an actor's rows are scoped to, or `None` when no
/// such actor exists. The one home for this read (package CD):
/// `ActorRepository::get_actor_tenancy` delegates here.
pub async fn actor_tenancy(
    pool: &PgPool,
    actor_id: Uuid,
) -> sqlx::Result<Option<(Uuid, Option<Uuid>)>> {
    let row = sqlx::query("SELECT user_id, org_id FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_optional(pool)
        .await?;
    row.map(|r| -> sqlx::Result<(Uuid, Option<Uuid>)> {
        Ok((r.try_get("user_id")?, r.try_get::<Option<_>, _>("org_id")?))
    })
    .transpose()
}
