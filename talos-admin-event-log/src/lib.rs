//! The ONE writer of `admin_event_log`.
//!
//! `admin_event_log` is an append-only operator audit trail (immutability
//! triggers refuse UPDATE, DELETE and TRUNCATE), so what a writer puts in a row
//! is what an auditor reads forever — and every summary on this platform
//! interpolates something a user chose: an API key's name, a model's name, a
//! workflow's name, an operator's note. Two protections belong at the write,
//! and until package CH (2026-09-17) only ONE writer of four applied both:
//!
//! * TRUNCATE the summary (1000 bytes, at a char boundary) and BOUND `details`
//!   (1 MiB) — an audit row must not be a place to store a megabyte.
//! * DLP-REDACT both — people paste secrets into name fields.
//!
//! Measured on pristine main: the canonical path in `talos-actor-repository`
//! did both; `talos-api-keys` redacted and never truncated; `talos-ml`'s
//! lifecycle job and `talos-worker-identity-repository` did neither, the former
//! under a comment asserting its summaries need no DLP pass because they are
//! "BUILT from fixed strings + model names" — the model name is user-supplied,
//! and the policy `details` it writes beside them are keyed by user-chosen
//! class labels.
//!
//! This is a LEAF crate for a measured reason: none of the three bypassing
//! crates depends on `talos-actor-repository` (and
//! `talos-worker-identity-repository` has no Talos dependency at all), so
//! hosting the shared writer there would have pulled the repository layer —
//! `talos-memory`, `talos-db`, the execution finalizer — into an operator CLI.
//! `talos-actor-repository` delegates to this crate instead.

use anyhow::Result;
use uuid::Uuid;

/// The summary cap, in bytes. MCP-1104's value, kept.
const MAX_SUMMARY_BYTES: usize = 1000;

/// Truncate a summary at a UTF-8 char boundary, marking that it was cut.
#[must_use]
pub fn truncate_summary(summary: &str) -> std::borrow::Cow<'_, str> {
    if summary.len() <= MAX_SUMMARY_BYTES {
        std::borrow::Cow::Borrowed(summary)
    } else {
        std::borrow::Cow::Owned(format!(
            "{}…",
            talos_text_util::truncate_at_char_boundary(summary, MAX_SUMMARY_BYTES - 3)
        ))
    }
}

/// Bound `details` at 1 MiB and redact it — measure first, then redact, so a
/// pathological input costs neither the regex pass nor the column.
#[must_use]
pub fn bound_details(details: Option<&serde_json::Value>) -> Option<serde_json::Value> {
    details.and_then(talos_dlp_provider::redact_json_bounded)
}

/// Append one operator-audit event on an existing connection.
///
/// `user_id` is `Option` because the worker-provisioning-token writer has no
/// platform user: those events come from the DB-credentialed operator CLI,
/// where holding the credential IS the authorization.
pub async fn insert_on_conn(
    conn: &mut sqlx::PgConnection,
    user_id: Option<Uuid>,
    event_type: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    summary: &str,
    details: Option<&serde_json::Value>,
) -> Result<()> {
    let truncated = truncate_summary(summary);
    let redacted_summary = talos_dlp_provider::redact_str(&truncated);
    let redacted_details = bound_details(details);
    sqlx::query(
        "INSERT INTO admin_event_log \
         (user_id, event_type, resource_type, resource_id, summary, details) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(user_id)
    .bind(event_type)
    .bind(resource_type)
    .bind(resource_id)
    .bind(&redacted_summary)
    .bind(redacted_details.as_ref())
    .execute(conn)
    .await?;
    Ok(())
}

/// Append one operator-audit event on a pool. The same statement and the same
/// two protections as [`insert_on_conn`] — writers that are not already inside
/// a transaction use this rather than their own INSERT.
pub async fn insert(
    pool: &sqlx::PgPool,
    user_id: Option<Uuid>,
    event_type: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    summary: &str,
    details: Option<&serde_json::Value>,
) -> Result<()> {
    let mut conn = pool.acquire().await?;
    insert_on_conn(
        &mut conn,
        user_id,
        event_type,
        resource_type,
        resource_id,
        summary,
        details,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_summary_is_passed_through_untouched() {
        let s = "Model 'inbox-classifier' promoted";
        assert!(matches!(truncate_summary(s), std::borrow::Cow::Borrowed(_)));
        assert_eq!(truncate_summary(s), s);
    }

    /// The cap is in BYTES and the cut lands on a char boundary — a summary
    /// carrying multi-byte text must not be truncated mid-character (which
    /// would panic on a naive slice).
    #[test]
    fn an_oversized_summary_is_cut_at_a_char_boundary() {
        let s = "é".repeat(2000); // 4000 bytes
        let out = truncate_summary(&s);
        assert!(out.len() <= MAX_SUMMARY_BYTES, "{} bytes", out.len());
        assert!(out.ends_with('…'), "the cut must be visible: {out:?}");
        assert!(out.chars().all(|c| c == 'é' || c == '…'));
    }

    /// Details are bounded AND redacted, so a secret pasted into an operator
    /// note does not become a permanent audit row.
    #[test]
    fn details_are_redacted() {
        let v = serde_json::json!({ "note": "token sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" });
        let out = bound_details(Some(&v)).expect("bounded");
        assert!(
            !out.to_string()
                .contains("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
            "{out}"
        );
        assert!(bound_details(None).is_none());
    }
}
