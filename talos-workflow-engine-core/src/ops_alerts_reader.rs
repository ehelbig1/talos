//! Read-side port for the ops-alerts triage store (`ops_alerts` domain).
//!
//! The `ops_alerts_digest` system node executes CONTROLLER-side — the
//! store is deliberately a controller-only data plane (no worker RPC,
//! workers stay credential-free), so the engine reaches it the same way
//! it reaches approvals: through an injected trait object
//! ([`crate::ApprovalGate`] is the structural precedent). The Postgres
//! impl lives in `talos-engine` (wired by the controller engine
//! builder); this crate stays persistence-free.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Fetch a triage snapshot for one user: digest counts over the active
/// set plus the top-N active alerts (severity-ordered).
#[async_trait]
pub trait OpsAlertsReader: Send + Sync {
    /// Returns a JSON object shaped:
    /// `{ "digest": { active_by_severity, active_by_source, new_last_24h,
    ///    reopened_active }, "top_active": [ {title, severity, source,
    ///    status, occurrence_count, corrected, ...} ] }`.
    ///
    /// `user_id` is the TENANT scope — impls MUST filter every query by
    /// it (it comes from the execution's resolved identity, never from
    /// node config). `top_limit` is caller-clamped but impls should
    /// defensively clamp again. `sources`, when `Some`, restricts
    /// `top_active` to those alert sources (an empty slice matches
    /// nothing); the `digest` counts stay over every active alert.
    async fn snapshot(
        &self,
        user_id: Uuid,
        top_limit: u32,
        sources: Option<&[String]>,
    ) -> Result<JsonValue, crate::BoxError>;
}

/// The most sources one digest node may name.
pub const MAX_ALERT_SOURCES: usize = 16;

/// Whether `s` can be an alert source name in a node's `sources` filter:
/// 1..=64 characters of ASCII letters, digits, `.`, `_` and `-`.
#[must_use]
pub fn usable_alert_source(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Read a node's `sources` value. Absent (or JSON null) → `None`, no
/// filter. Present → `Some` of its usable entries, at most
/// [`MAX_ALERT_SOURCES`], deduplicated in order. A present value with no
/// usable entry — a string instead of a list, all entries malformed — is
/// `Some(vec![])`, which matches NOTHING: a filter written to narrow what
/// reaches a reader must not, by being malformed, widen to everything.
#[must_use]
pub fn parse_alert_sources(v: Option<&JsonValue>) -> Option<Vec<String>> {
    let v = v.filter(|v| !v.is_null())?;
    let mut out: Vec<String> = Vec::new();
    for s in v
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
    {
        if usable_alert_source(s) && !out.iter().any(|o| o == s) && out.len() < MAX_ALERT_SOURCES {
            out.push(s.to_string());
        }
    }
    Some(out)
}

#[cfg(test)]
mod source_filter_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_or_null_is_no_filter() {
        assert_eq!(parse_alert_sources(None), None);
        assert_eq!(parse_alert_sources(Some(&JsonValue::Null)), None);
    }

    #[test]
    fn usable_entries_are_kept_once_in_order() {
        let v = json!(["talos", "backup-drill", "talos", "github.actions_1"]);
        assert_eq!(
            parse_alert_sources(Some(&v)),
            Some(vec![
                "talos".into(),
                "backup-drill".into(),
                "github.actions_1".into()
            ])
        );
    }

    #[test]
    fn a_malformed_filter_matches_nothing_rather_than_everything() {
        for v in [
            json!("talos"),
            json!(["", "a b", "x;drop"]),
            json!([1, 2]),
            json!({}),
        ] {
            assert_eq!(parse_alert_sources(Some(&v)), Some(vec![]), "{v}");
        }
    }

    #[test]
    fn at_most_sixteen() {
        let many: Vec<String> = (0..40).map(|i| format!("s{i}")).collect();
        assert_eq!(
            parse_alert_sources(Some(&json!(many))).unwrap().len(),
            MAX_ALERT_SOURCES
        );
    }
}
