//! Teacher-audit ceiling snapshot — the `assistant_report` system node's
//! per-model teacher-vs-gold ceiling section. Read-only, tenant-scoped by
//! `user_id`; returns JSON directly (the report node's output IS graph
//! data, so there is no typed consumer to serve).
//!
//! The ceiling is the `accuracy` field of `ml_models.teacher_audit` — the
//! stored result of the weekly automatic teacher audit
//! (`teacher_audit_job`). The JSONB holds only the LATEST audit, so no
//! delta-vs-previous is derivable here; `trend_available: false` signals
//! that a history table would be needed for trend (deliberately not built
//! in this pass).

use anyhow::Result;
use serde_json::{json, Value as JsonValue};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Per-model teacher-audit ceiling: status, ceiling accuracy, rows
/// compared, parse failures, per-class agreement, and the completion
/// timestamp. Only models that have been audited at least once
/// (`teacher_audit IS NOT NULL`) appear — an un-audited fleet yields an
/// empty `models` array (the report section degrades gracefully).
pub async fn teacher_ceilings(pool: &PgPool, user_id: Uuid) -> Result<JsonValue> {
    let rows = sqlx::query(
        "SELECT name, teacher_audit \
         FROM ml_models \
         WHERE user_id = $1 AND teacher_audit IS NOT NULL \
         ORDER BY name LIMIT 50",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut models = Vec::with_capacity(rows.len());
    for r in rows {
        let name: String = r.try_get("name")?;
        let audit: Option<JsonValue> = r.try_get::<Option<JsonValue>, _>("teacher_audit")?;
        // NULL was filtered in SQL; JSON `null` is still possible — skip it
        // so a malformed stamp doesn't surface as an empty model row.
        let Some(audit) = audit.filter(|v| !v.is_null()) else {
            continue;
        };

        let status = audit
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Ceiling + per-class agreement + parse failures + timestamp. All
        // read as passthrough JSON (`.get`) — absent fields render as
        // `null`, which the report/renderer treats as "not measured".
        // `per_class` labels are class names (e.g. "archive"), not PII;
        // the disagreement `mismatches` array is intentionally NOT
        // surfaced here.
        models.push(json!({
            "name": name,
            "status": status,
            "ceiling_accuracy": audit.get("accuracy"),
            "compared": audit.get("compared"),
            "parse_failed": audit.get("parse_failed"),
            "per_class": audit.get("per_class"),
            "audited_at": audit.get("audited_at"),
        }));
    }

    Ok(json!({
        "models": models,
        // The teacher_audit JSONB stores only the latest audit, so a
        // delta vs the previous audit is not derivable. Reporting
        // current-only; a trend line would require a history table (not
        // built in this pass).
        "trend_available": false,
    }))
}
