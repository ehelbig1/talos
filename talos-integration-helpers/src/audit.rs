//! Shared writers for the cross-integration channel-lifecycle audit
//! log (`google_calendar_audit_log` — the name is inherited from the
//! first integration; it functions as the shared integration-events
//! log for every push integration).

use serde_json::Value as JsonValue;
use uuid::Uuid;

/// One channel-lifecycle audit row. `target` lands in the log's
/// `calendar_id` column — the shared "which upstream target" slot
/// (gcal stores the calendar id, gmail stores the mailbox address).
pub struct ChannelAuditEvent<'a> {
    pub integration_id: Option<Uuid>,
    pub user_id: Uuid,
    pub event_type: &'a str,
    pub target: Option<&'a str>,
    pub success: bool,
    /// MUST already be truncated + DLP-redacted (see
    /// [`truncate_and_redact_error`]) — this writer does not scrub.
    pub error_message: Option<&'a str>,
    pub metadata: JsonValue,
}

/// Insert one audit row. Callers own failure logging (the historical
/// per-site messages differ: `"audit log insert failed"` in the
/// schedulers, `"<integ> channel_<x> audit log insert failed"` in the
/// watch services) so this returns the raw `sqlx::Error`.
pub async fn insert_channel_audit(
    pool: &sqlx::PgPool,
    ev: ChannelAuditEvent<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO google_calendar_audit_log \
         (integration_id, user_id, event_type, calendar_id, success, error_message, metadata) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(ev.integration_id)
    .bind(ev.user_id)
    .bind(ev.event_type)
    .bind(ev.target)
    .bind(ev.success)
    .bind(ev.error_message)
    .bind(ev.metadata)
    .execute(pool)
    .await
    .map(|_| ())
}

/// The canonical persistence-boundary scrub for upstream API error
/// text (MCP-980 + MCP-1181): truncate at 1 KiB FIRST (so a verbose
/// Google error envelope can't amplify regex-pass cost or blow past
/// reasonable column-storage size), then DLP-redact (OAuth failure
/// responses commonly echo `invalid_token` / `invalid_grant` with the
/// offending refresh_token bytes in the error description).
///
/// Use before persisting ANY upstream error string into
/// `error_message` columns.
pub fn truncate_and_redact_error(raw: &str) -> String {
    let truncated: &str = if raw.len() > 1024 {
        talos_text_util::truncate_at_char_boundary(raw, 1024)
    } else {
        raw
    };
    talos_dlp_provider::redact_str(truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_and_redact_caps_at_1_kib() {
        let long = "x".repeat(4096);
        let out = truncate_and_redact_error(&long);
        assert!(out.len() <= 1024, "expected ≤1024 bytes, got {}", out.len());
    }

    #[test]
    fn truncate_and_redact_passes_short_text_through() {
        assert_eq!(
            truncate_and_redact_error("HTTP 503 Service Unavailable"),
            "HTTP 503 Service Unavailable"
        );
    }
}
