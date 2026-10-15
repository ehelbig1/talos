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

/// Insert one audit row unless the same user already has a row of this
/// `event_type` for this channel (`metadata.channel_uuid`) from the last 24
/// hours. `Ok(true)` when the row was written.
///
/// For a refusal an outsider can provoke at will: one row a day per channel
/// is what the owner's `recent_failure` view (a 25-hour look-back) needs, and
/// every refusal past it is a metric, not a row. One statement, so the cap
/// costs no extra round trip; two refusals racing on the first write of a
/// day may both land, which bounds the row count at a small multiple of one.
pub async fn insert_channel_audit_once_per_day(
    pool: &sqlx::PgPool,
    ev: ChannelAuditEvent<'_>,
    channel_uuid: Uuid,
) -> Result<bool, sqlx::Error> {
    let channel_uuid = channel_uuid.to_string();
    let mut metadata = ev.metadata;
    if let Some(map) = metadata.as_object_mut() {
        map.insert("channel_uuid".into(), JsonValue::from(channel_uuid.clone()));
    }
    let written = sqlx::query(
        "INSERT INTO google_calendar_audit_log \
         (integration_id, user_id, event_type, calendar_id, success, error_message, metadata) \
         SELECT $1, $2, $3, $4, $5, $6, $7 \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM google_calendar_audit_log \
             WHERE user_id = $2 AND event_type = $3 \
               AND metadata->>'channel_uuid' = $8 \
               AND created_at > now() - interval '24 hours')",
    )
    .bind(ev.integration_id)
    .bind(ev.user_id)
    .bind(ev.event_type)
    .bind(ev.target)
    .bind(ev.success)
    .bind(ev.error_message)
    .bind(metadata)
    .bind(channel_uuid)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(written == 1)
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
